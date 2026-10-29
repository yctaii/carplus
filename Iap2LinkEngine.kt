package io.github.shaonialife.cardeck.iap2

import java.io.ByteArrayOutputStream

/** 手机端回显 SYN|ACK 时声明的发送窗口（真机 iPhone / AADisplay 同值 0x7F）。 */
private const val PHONE_DECLARED_MAX_OUTGOING = 0x7F

/**
 * iAP2 链路引擎（发送端实现；链路层协议对称，本实现按「发起方」工作）。
 *
 * 握手（无线模式，手机为发起方——DiPlay/xcertplay 的 openWireless 以
 * initiateNegotiation=false 等待手机发起）：
 *  1. start() 发送 marker `FF 55 02 00 EE 10`，随即发送同步包（FF5A 帧，
 *     control=0x80，载荷 = SynchronizationPayload）
 *  2. 对端收到 marker 后进入协商并发送自己的同步包；双方收到同步包即回 ACK
 *  3. 协商状态下收到 ACK 即进入 NORMAL（控制会话 10 可用）
 *
 * 数据帧：control=0x40（捎带 ACK），seq=发送序号（u8 回绕，初始 99），
 * ack=已按序收到的最新序号，sessionId=10。对端 marker 会被帧头扫描自然丢弃。
 *
 * 协议语义参照 reference/xcertplay transport/Iap2LinkEngine.kt（独立重写）。
 * 简化项（RFCOMM 为可靠有序流）：不做乱序缓冲与主动 EAK，保留重复帧检测、
 * 发送窗口与重传计时。
 */
class Iap2LinkEngine(
    private val maxOutgoing: Int = 4,
    private val retransmissionTimeoutMillis: Long = 4_000L,
    private val maxRetransmissions: Int = 4,
) {
    enum class State { IDLE, NEGOTIATING, NORMAL, DEAD }

    data class SessionDescriptor(
        val id: Int,
        val kind: Int,
        val version: Int,
    )

    data class SynchronizationPayload(
        val maxOutgoing: Int,
        val maxLength: Int,
        val retransmissionTimeoutMillis: Int,
        val acknowledgementTimeoutMillis: Int,
        val maxRetransmissions: Int,
        val maxAcknowledgements: Int,
        val sessions: List<SessionDescriptor>,
    ) {
        fun encode(): ByteArray {
            val out = ByteArrayOutputStream(10 + sessions.size * 3)
            out.write(SYNCHRONIZATION_VERSION)
            out.write(maxOutgoing)
            writeU16(out, maxLength)
            writeU16(out, retransmissionTimeoutMillis)
            writeU16(out, acknowledgementTimeoutMillis)
            out.write(maxRetransmissions)
            out.write(maxAcknowledgements)
            sessions.forEach {
                out.write(it.id)
                out.write(it.kind)
                out.write(it.version)
            }
            return out.toByteArray()
        }

        companion object {
            fun decode(bytes: ByteArray): SynchronizationPayload? {
                if (bytes.size < 10 || u8(bytes[0]) != SYNCHRONIZATION_VERSION) return null
                val sessions = ArrayList<SessionDescriptor>()
                var offset = 10
                while (offset + 3 <= bytes.size) {
                    sessions +=
                        SessionDescriptor(
                            u8(bytes[offset]),
                            u8(bytes[offset + 1]),
                            u8(bytes[offset + 2]),
                        )
                    offset += 3
                }
                return SynchronizationPayload(
                    maxOutgoing = u8(bytes[1]),
                    maxLength = readU16(bytes, 2),
                    retransmissionTimeoutMillis = readU16(bytes, 4),
                    acknowledgementTimeoutMillis = readU16(bytes, 6),
                    maxRetransmissions = u8(bytes[8]),
                    maxAcknowledgements = u8(bytes[9]),
                    sessions = sessions,
                )
            }
        }
    }

    sealed class Event {
        class Control(
            val bytes: ByteArray,
        ) : Event()

        class Dead(
            val reason: String?,
        ) : Event()
    }

    private class Packet(
        var sequence: Int,
        val payload: ByteArray,
        var retransmissions: Int = 0,
        var deadlineMillis: Long = 0,
        val awaitAck: Boolean = true,
    )

    var state: State = State.IDLE
        private set
    var peerSynchronization: SynchronizationPayload? = null
        private set

    private var sentSequence = INITIAL_SEQUENCE
    private var lastSentAcknowledged: Int? = null
    private var lastReceivedInOrder = 0

    /**
     * 采纳的对端控制会话 ID（收到对端 sync 载荷时确定）。
     * Audi 真车字节级实测（2026-10-09）：车机（MIB3）以发起方姿态发 SYN，声明
     * 会话表 {1:control, 2:EA}，手机回显其表后它以 **1 号会话**通信——
     * CSM 发在 10 号会被静默丢弃（链路层照常 ACK，极具迷惑性）。
     * 测试台 DiPlay/xcertplay 声明 10，采纳后与本表默认一致，行为不变。
     */
    private var adoptedPeerControlSessionId: Int? = null

    /** 采纳的对端 sync 载荷（协商回显/诊断用）。 */
    private var adoptedSynchronization: SynchronizationPayload? = null

    /**
     * 隧道（type-130）协商模式。DiPlay 的隧道链路引擎（Iap2LinkEngine.openTunnel，
     * initiateNegotiation=true）有两个硬性期望（2026-08 字节级对照源码）：
     *  1. 收到「ACK 但尚未收到对端 SYN」时立即判链路失败（die）——因此回显必须**先于**
     *     裸 ACK 发出（回显帧 control=SYN|ACK 自带确认位，一帧即可完成对端协商）；
     *  2. 其隧道为零 ACK 模式（maxRetransmissions=0/maxAcknowledgements=0），不会回
     *     任何 ACK——等待「对端 ACK」完成协商会死锁，回显即视为协商完成。
     * 默认 false：蓝牙（RFCOMM/事件通道）路径语义不变（Audi 需 ACK+回显、等最终 ACK）。
     */
    var echoFirst: Boolean = false

    /** 诊断：首次采纳对端会话表时回调（打印对端提议的会话表，便于真车排查）。 */
    var onPeerSynchronizationAdopted: ((SynchronizationPayload) -> Unit)? = null

    /** 诊断：丢弃未知会话 ID 的数据帧时回调（(sessionId, bytes)）。 */
    var onUnknownSessionData: ((Int, Int) -> Unit)? = null

    /**
     * EA 会话（2 号）数据帧回调：设置后 EA 帧不再被当作未知会话丢弃，
     * 而是交由此回调（事件通道虚拟链路上的触摸 HID 载体）。
     */
    var onEaData: ((bytes: ByteArray) -> Unit)? = null

    /** 诊断：每个入向链路帧的摘要（control/seq/ack/sessionId/载荷长度），真车排查用。 */
    var onFrameReceived: ((control: Int, sequence: Int, ack: Int, sessionId: Int, size: Int) -> Unit)? = null

    /** 诊断：每个出向链路帧的摘要（仅链路层帧，用于对照真车协商时序）。 */
    var onFrameSent: ((control: Int, sequence: Int, ack: Int, sessionId: Int, size: Int) -> Unit)? = null

    private var unknownSessionDropped = 0

    private val unacknowledged = ArrayList<Packet>()
    private val sendBacklog = ArrayDeque<Packet>()
    private val pendingEvents = ArrayDeque<Event>()
    private val output = ByteArrayOutputStream()
    private val receive = ReceiveBuffer()

    private var markerDeadline: Long? = null
    private var syncDeadline: Long? = null
    private var retransmitDeadline: Long? = null

    /** 上一次回显 SYN 时对端的 SYN 序号与我方序号（重传同一 SYN 时原样重放）。 */
    private var lastEchoPeerSequence: Int? = null
    private var lastEchoOwnSequence = 0

    /** NORMAL 状态下连续收到的对端探测 marker（FF 55 02 00 EE 10）计数。 */
    private var normalDetectMarkers = 0

    /** 对端 0x1D01 识别帧（param 7）声明可接收的消息 ID 集合；null = 对端未声明（如单测）。 */
    private var peerDeclaredReceiveIds: Set<Int>? = null

    /**
     * 对端 0x1D01 是否属于非 MIB3 / Cinemo 栈（MFi AuthV3 EC 身份只接受 32B 挑战）：
     * VirtualIap2Link 的冷启动基线是 20B 优先，而别克 E2YB（Cinemo）在隧道侧收到 20B 挑战后
     * 120ms 内会直接把隧道链路复位回 FF55 Detecting 态，并在 ~12s 看门狗到期时拆掉整条 CarPlay 会话
     * （2026-10-27 171207 日志定谳）。识别到此类车机时：① 预写 MfiLengthMemory 记忆 32B；
     * ② 若上层首帧 0xAA02 仍发了 20B，在链路层直接升级为 32B 挑战。
     */
    private var peerPrefers32ByteMfiChallenge: Boolean = false
    private var mfiChallengeUpgraded: Boolean = false

    /** 诊断：对端在 NORMAL 状态下重置回探测态（连续发 marker）并触发重协商时回调。 */
    var onPeerResetToDetect: (() -> Unit)? = null

    val isDead: Boolean get() = state == State.DEAD

    /** 本引擎是否发起过 SYN（start=发起方；enterNegotiating/startResponder=响应方）。 */
    private var originatedSyn = false

    /**
     * **本方声明的发送窗口**（LSP maxOutgoing 语义 = 声明方自己的未确认包上限）：
     * 发送窗口按此计，而非对端声明值——回显时我们会声明 0x7F（ownSyncOf），
     * 按对端值计窗会把突发消息卡死在对端的小窗口里（MIB3 突发 8 条 × 对端 4）。
     */
    private var declaredMaxOutgoing = maxOutgoing

    /** 进入协商：发 marker + 同步包（发送端=发起方，不等待对端 marker）。 */
    fun start(nowMillis: Long) {
        if (state != State.IDLE) return
        originatedSyn = true
        state = State.NEGOTIATING
        appendOutput(MARKER)
        markerDeadline = nowMillis + MARKER_RESEND_MILLIS
        sendSynchronization()
        syncDeadline = nowMillis + SYNC_RESEND_MILLIS
    }

    /**
     * 补发协商开场：marker + 本表同步包（允许从 [State.NEGOTIATING] 再次触发）。
     *
     * 用于「对端只发 marker、不发同步包」的形态——它在等**我们**的会话表。
     * Honda HFT（Alpine 8A250-30A）2026-10-20 事件通道实测：车机在 60 秒里发了
     * 60 个 marker `FF 55 02 00 EE 10`，一条 FF5A 同步包都没有（说明它卡在探测态），
     * 而我们此前只回 marker，于是车机一直重发、链路永远建不起来。
     * 对照同一条车机的蓝牙 iAP2 链路：手机首帧正是「marker + FF5A SYN」，车机
     * 50ms 内即回自己的会话表——事件通道上补齐同一组合即可推进。
     */
    fun initiate(nowMillis: Long) {
        if (state == State.DEAD) return
        originatedSyn = true
        if (state == State.IDLE) state = State.NEGOTIATING
        appendOutput(MARKER)
        markerDeadline = nowMillis + MARKER_RESEND_MILLIS
        sendSynchronization()
        syncDeadline = nowMillis + SYNC_RESEND_MILLIS
    }

    /**
     * 停止协商期的自动重发（marker / 同步包），状态保持不变。
     *
     * 用于「对端一直不回同步包」的场景：控制通道上一旦无限 500ms 打点，会把对端
     * CarPlay 栈刷懵（2026-10-11 事件通道实测过的坑），所以由上层按轮次重开、轮次
     * 用尽后显式停手。
     */
    fun stopNegotiationRetries() {
        markerDeadline = null
        syncDeadline = null
    }

    /**
     * 应答者模式：只发 marker，**不发 SYN**——等对端（车机）自己发 SYN 再 ACK+回显。
     * 奥迪事件通道虚拟链路实测（2026-10-11）：车机发 marker 开场后由它发起 SYN；
     * 我们主动发 SYN（且被 500ms 重发洪水放大）会把车机 CarPlay 栈打懵——
     * 表现为事件通道再无响应、连蓝牙链路的 ACK 都停了。
     */
    fun startResponder(nowMillis: Long) {
        if (state != State.IDLE) return
        state = State.NEGOTIATING
        appendOutput(MARKER)
        markerDeadline = nowMillis + MARKER_RESEND_MILLIS
        // syncDeadline 保持 null：不主动发 SYN、不重发 SYN
    }

    /**
     * 静默进入协商（DETECT 语义，对照 catplay LinkLayer server 角色）：
     * 不发任何字节——对端（客户端）每 200ms 重发 DETECT，我们**收到一次回一次**、
     * 绝不主动重发（服务器重发 DETECT 会把客户端状态机打回 Detecting，
     * SYN 永远出不来——2026-10-11 事件通道实测）。
     */
    fun enterNegotiating() {
        if (state != State.IDLE) return
        state = State.NEGOTIATING
    }

    fun feed(
        bytes: ByteArray,
        nowMillis: Long,
    ) {
        if (state == State.DEAD) return
        var offset = 0
        while (offset < bytes.size && state != State.DEAD) {
            val room = receive.remainingCapacity()
            if (room == 0) {
                die("inbound frame exceeds limit")
                return
            }
            val count = minOf(room, bytes.size - offset)
            receive.append(bytes, offset, count)
            offset += count
            while (parseAvailable(nowMillis) && state != State.DEAD) {
                // 排空所有完整帧
            }
        }
    }

    fun feedEof() = die(null)

    fun takeOutput(): ByteArray {
        val bytes = output.toByteArray()
        output.reset()
        return bytes
    }

    fun pollEvent(): Event? = if (pendingEvents.isEmpty()) null else pendingEvents.removeFirst()

    fun nextDeadlineMillis(): Long? = listOfNotNull(markerDeadline, syncDeadline, retransmitDeadline).minOrNull()

    fun advanceTime(nowMillis: Long) {
        if (state == State.DEAD) return
        if (markerDeadline != null && markerDeadline!! <= nowMillis) {
            markerDeadline = null
            if (state == State.NEGOTIATING && appendOutput(MARKER)) {
                markerDeadline = nowMillis + MARKER_RESEND_MILLIS
            }
        }
        if (syncDeadline != null && syncDeadline!! <= nowMillis) {
            syncDeadline = null
            if (state == State.NEGOTIATING) {
                // 已采纳对端表：只补裸 ACK（回显仅首次发一次，避免协商轮次膨胀）；
                // 未采纳：继续重发本表 SYN（测试台时序）
                if (adoptedSynchronization != null) {
                    sendAcknowledgement()
                } else {
                    sendSynchronization()
                }
                syncDeadline = nowMillis + SYNC_RESEND_MILLIS
            }
        }
        if (retransmitDeadline != null && retransmitDeadline!! <= nowMillis) {
            retransmitDeadline = null
            if (state == State.NORMAL) retransmitDue(nowMillis)
        }
    }

    /**
     * 排入一个完整的控制会话载荷。窗口满时进入积压队列，由 ACK 或 pump 驱动重试。
     * 返回 false 仅代表链路已死。
     *
     * [awaitAck]=false：发后不管——不计入未确认清单、不重传，**链路不会因它未被 ACK
     * 而死亡**。用于 Audi 实测中「接受但从不 ACK」的消息（0x4E0E 传输标识：车机对
     * 其他包毫秒级 ACK、唯独不认它，重传看门狗曾据此在 +20s 杀掉整条蓝牙链路）。
     */
    fun sendControl(
        bytes: ByteArray,
        nowMillis: Long,
        awaitAck: Boolean = true,
    ): Boolean {
        if (state == State.DEAD) return false
        var effective = bytes
        val declared = peerDeclaredReceiveIds
        if (declared != null &&
            bytes.size >= 6 &&
            bytes[0] == 0x40.toByte() &&
            bytes[1] == 0x40.toByte()
        ) {
            val frameLen = readU16(bytes, 2)
            if (frameLen == bytes.size) {
                val msgId = readU16(bytes, 4)
                if ((msgId == 0xA100 || msgId == 0xFFFA || msgId == 0xFFF0) && msgId !in declared) {
                    // 隧道突发兼容：车机 0x1D01 明确未声明接收 MIB3 私有消息（如别克 Cinemo 栈）时跳过，防车机重置链路
                    return true
                }
                if ((msgId == 0x4E0C || msgId == 0x4E0A || msgId == 0x4E09) &&
                    bytes.size >= 10 &&
                    bytes.last() != 0.toByte()
                ) {
                    // VirtualIap2Link 突发里 0x4E0C/0x4E0A/0x4E09 的 UTF-8 字符串未带尾部 NUL：对严格校验的 Cinemo 栈补齐 \0
                    effective = Iap2Csm.encode(msgId, Iap2Csm.param(0, bytes.copyOfRange(10, bytes.size) + byteArrayOf(0)))
                }
                if (msgId == Iap2MessageIds.MFI_REQUEST_CHALLENGE &&
                    peerPrefers32ByteMfiChallenge &&
                    !mfiChallengeUpgraded &&
                    bytes.size == 30
                ) {
                    // 兜底防线：若隧道侧首次 0xAA02 仍携带 20B 挑战（总长 30B），对非 MIB3/Cinemo 车机直接升级为 32B，
                    // 防止车机收到 20B 后立即复位隧道链路并在 ~12s 后拆掉整条 CarPlay 会话
                    mfiChallengeUpgraded = true
                    val challenge32 = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
                    effective = Iap2Csm.encode(msgId, Iap2Csm.param(0, challenge32))
                }
            }
        }
        val limit = (peerSynchronization?.maxLength ?: 0xFFFF) - HEADER_BYTES - 1
        if (limit <= 0 || effective.size > limit) {
            die("control payload ${effective.size} exceeds negotiated limit $limit")
            return false
        }
        sendBacklog += Packet(0, effective.copyOf(), awaitAck = awaitAck)
        drainSendWindow(nowMillis)
        return true
    }

    // ---- 接收解析 ----

    private fun parseAvailable(nowMillis: Long): Boolean {
        // 丢弃帧头前的杂字节（含对端 marker FF55…）
        while (receive.size >= 2 &&
            !(receive[0] == 0xFF.toByte() && receive[1] == 0x5A.toByte())
        ) {
            if (receive[0] == 0xFF.toByte() && receive[1] == 0x55.toByte()) {
                if (receive.size < MARKER.size) return false
                if (isMarkerAtHead()) {
                    receive.discard(MARKER.size)
                    if (state == State.NORMAL) {
                        normalDetectMarkers = 0
                        renegotiateAfterPeerDetect(nowMillis)
                        return false
                    }
                    continue
                }
            }
            receive.discard(1)
        }
        if (receive.size < HEADER_BYTES) return false
        val header = receive.peek(HEADER_BYTES)
        if (!checksumValid(header)) {
            receive.discard(1)
            return true
        }
        val length = readU16(header, 2)
        if (length < HEADER_BYTES) {
            receive.discard(1)
            return true
        }
        if (receive.size < length) return false
        val frame = receive.take(length)
        val payloadWithChecksum = frame.copyOfRange(HEADER_BYTES, length)
        if (payloadWithChecksum.isNotEmpty() && !checksumValid(payloadWithChecksum)) {
            receive.discard(1)
            return true
        }
        val payload =
            if (payloadWithChecksum.isEmpty()) {
                null
            } else {
                payloadWithChecksum.copyOf(payloadWithChecksum.size - 1)
            }
        processFrame(
            control = u8(frame[4]),
            sequence = u8(frame[5]),
            ack = u8(frame[6]),
            sessionId = u8(frame[7]),
            payload = payload,
            nowMillis = nowMillis,
        )
        return true
    }

    private fun processFrame(
        control: Int,
        sequence: Int,
        ack: Int,
        sessionId: Int,
        payload: ByteArray?,
        nowMillis: Long,
    ) {
        normalDetectMarkers = 0
        onFrameReceived?.invoke(control, sequence, ack, sessionId, payload?.size ?: 0)
        if (control and CONTROL_RESET != 0) {
            die("peer sent reset")
            return
        }
        if (control and CONTROL_SYNCHRONIZE != 0) {
            val sync = SynchronizationPayload.decode(payload ?: ByteArray(0))
            // echoFirst 模式下即使本引擎已 NORMAL 也继续处理对端 SYN 重发：对端引擎
            // （DiPlay openTunnel）只从 TCP 读，若其 SYN 到达时我方隧道尚未建立，
            // 首次回显会走错通道；其 500ms 的 SYN 重发让我们在隧道就绪后补上回显
            // （parseAvailable 的帧扫描会丢弃重发中的 FF55 marker，无副作用）。
            //
            // **只有纯 SYN（不带 ACK 位）才回 SYN|ACK**：SYN|ACK 说明对端在回应我们的
            // 发起方 SYN，属于「它已应答」的信号（见下方 ACK 分支），再回一条就会形成
            // 双方互回 SYN|ACK 的无限乒乓（单测暴露：两个引擎互相喂帧时协商永不收敛）。
            val isPureSyn = (control and CONTROL_ACKNOWLEDGEMENT) == 0
            if (sync != null && isPureSyn && (state == State.NEGOTIATING || echoFirst)) {
                val firstAdoption = adoptedSynchronization == null
                peerSynchronization = sync
                if (firstAdoption) adoptedSynchronization = sync
                // Audi 真车实测（2026-10-09，字节级对照）：车机以发起方姿态发 SYN 声明其会话表
                // {1:control,2:EA}，手机必须「ACK + 原样回显其表（SYN|ACK）」——车机见到回显才发
                // 最终 ACK 完成协商（只回裸 ACK 时它永不回 ACK）。回显即声明「我采纳你的表」，
                // 之后 CSM 走采纳表的控制会话 ID（1）；发 10 会被静默丢弃。
                sync.sessions.firstOrNull { it.kind == CONTROL_KIND }?.let {
                    adoptedPeerControlSessionId = it.id
                }
                lastReceivedInOrder = sequence
                // **每次** SYN 都只回一帧 SYN|ACK（不回裸 ACK）：
                //  ① 语义完整：SYN|ACK 自带确认位与 ack 字段，裸 ACK 是冗余的
                //     （catplay `on_recv_neg_host` 正是只发 SYN+ACK）；
                //  ② 序号不能撞：裸 ACK 用当前 sentSequence，而 SYN|ACK 会自增，下一次
                //     裸 ACK 就复用上一帧 SYN|ACK 的序号——BMW 把同序号帧当重复丢弃；
                //  ③ 重传同一 SYN 时整帧原样重放，字节级幂等。
                // 2026-10-19 BMW 87866 定谳：旧实现在首次采纳后只回裸 ACK，该车机每轮
                // 重试都用新序号重开协商（161→191→40…），因此 14 轮全部卡在协商、
                // 一次 0x1D00 都没走到（日志：133 条 SYN / 0 条 ACK）。
                sendSynchronizationEcho(sync, sequence)
                if (firstAdoption) onPeerSynchronizationAdopted?.invoke(sync)
                // 响应方（未发过 SYN）回显即视为协商完成：对端见到 SYN|ACK 后即认为
                // 链路可用（MIB3 真机 iPhone 发完 SYN|ACK 立即发 0x1D00，不等 ACK）；
                // 发起方仍等对端 ACK/数据（原语义）
                if (echoFirst || !originatedSyn) completeNegotiationIfPending(nowMillis)
            } else if (sync != null &&
                !isPureSyn &&
                adoptedSynchronization == null &&
                state == State.NEGOTIATING
            ) {
                // 发起方收到 SYN|ACK（对端对我们 SYN 的应答，载荷=对端表）：
                // 只采纳、**不回显**（回显会形成互回 SYN|ACK 的乒乓）。此前只在纯
                // SYN 上采纳，对端是「纯响应方」时发起方永远到不了 NORMAL——
                // MIB3 虚拟链路（手机 arm detect → 车机 SYN → 手机 SYN|ACK）正是
                // 这个形态：车机侧由本分支收敛，随后按超时机制补裸 ACK。
                peerSynchronization = sync
                adoptedSynchronization = sync
                sync.sessions.firstOrNull { it.kind == CONTROL_KIND }?.let {
                    adoptedPeerControlSessionId = it.id
                }
                // Watermark must also advance (the pure SYN branch does the same): when left at 0,
                // the initiator treats the responder's first data frame as an "expired frame", only re-sending ack=0 —
                // the responder's send window gets poisoned by this bogus ack (backlog never flushes, unit test located)
                lastReceivedInOrder = sequence
                completeNegotiationIfPending(nowMillis)
            }
        }
        if (control and CONTROL_ACKNOWLEDGEMENT != 0) {
            handleAcknowledgement(ack, nowMillis)
        }
        val isDataFrame =
            payload != null &&
                (control and CONTROL_ACKNOWLEDGEMENT) != 0 &&
                (control and CONTROL_SYNCHRONIZE) == 0 &&
                (control and CONTROL_EXTENDED_ACKNOWLEDGEMENT) == 0
        if (isDataFrame) {
            // 控制消息的会话 ID：本国表 10 或采纳表（Audi=1；测试台两者一致）
            if (sessionId == SESSION_CONTROL || sessionId == adoptedPeerControlSessionId) {
                // 收到对端的数据即代表对端认为链路可用；ACK 帧若丢失/被跳过，这里兜底进入 NORMAL
                completeNegotiationIfPending(nowMillis)
                handleData(sequence, payload!!)
            } else if (sessionId == SESSION_EA && onEaData != null) {
                // EA 会话数据（含触摸 HID）：对端序号账法与控制会话独立，直接上抛
                onEaData?.invoke(payload!!)
                sendAcknowledgement()
            } else {
                reportUnknownSessionData(sessionId, payload!!.size)
            }
        }
    }

    private fun completeNegotiationIfPending(nowMillis: Long) {
        if (state == State.NEGOTIATING && peerSynchronization != null) {
            state = State.NORMAL
            normalDetectMarkers = 0
            markerDeadline = null
            syncDeadline = null
            drainSendWindow(nowMillis)
        }
    }

    private fun isMarkerAtHead(): Boolean {
        if (receive.size < MARKER.size) return false
        for (i in MARKER.indices) {
            if (receive[i] != MARKER[i]) return false
        }
        return true
    }

    /**
     * 对端在 NORMAL 状态下连续发探测 marker（FF 55 02 00 EE 10），说明车机侧链路状态机已复位
     * 回到 Detecting 态（2026-10-27 别克 E2YB / Cinemo 实车日志：收 0x4300 后 ~250ms 起以 1Hz
     * 持续发 FF 55 02 00 EE 10，不再回任何 FF5A 帧）。若继续静默丢弃 marker，对端永远卡在探测态。
     * 此处复位链路层重开协商（回 marker + 本表 SYN），并通知会话层重新走识别/认证。
     */
    private fun renegotiateAfterPeerDetect(nowMillis: Long) {
        state = State.NEGOTIATING
        peerSynchronization = null
        adoptedSynchronization = null
        adoptedPeerControlSessionId = null
        lastEchoPeerSequence = null
        lastSentAcknowledged = null
        unacknowledged.clear()
        sendBacklog.clear()
        retransmitDeadline = null
        originatedSyn = true
        appendOutput(MARKER)
        markerDeadline = nowMillis + MARKER_RESEND_MILLIS
        sendSynchronization()
        syncDeadline = nowMillis + SYNC_RESEND_MILLIS
        onPeerResetToDetect?.invoke()
    }

    private fun reportUnknownSessionData(
        sessionId: Int,
        size: Int,
    ) {
        unknownSessionDropped++
        if (unknownSessionDropped <= 5) onUnknownSessionData?.invoke(sessionId, size)
    }

    /** 诊断：出向同步包回显已生成（隧道模式用于「回显已送达后才允许发 CSM」门闸）。 */
    var onSynchronizationEchoSent: (() -> Unit)? = null

    /**
     * 回显对端 sync（SYN|ACK，载荷与对端完全一致）——声明「手机采纳车机会话表」。
     *
     * **必须消耗一个新发送序号**：对端按自己的序号账法校验回包（catplay
     * `NegotiationTx::SynAck` 用 `take_own_seq()` 自增）。旧实现复用 `sentSequence`
     * （发 SYN 后从未自增），于是 SYN 与 SYN-ACK 同为 seq=99，BMW 判为重复帧丢弃——
     * 14 轮协商全部超时、车机一条 ACK 都没回（2026-10-19 实车日志定谳）。
     *
     * 对**同一个** SYN 的重发保持字节级幂等：重放上次那一帧，不推进序号。
     * DiPlay 隧道模式每 500ms 重发同一 SYN，靠这条维持原有行为。
     */

    /**
     * 回显用的「我方参数」：会话表/超时沿用对端声明（手机端无特殊要求），
     * 但 **maxOutgoing 提到 0x7F**——原样回显会把我们自己的发送窗口限死在对端的
     * 小窗口（MIB3 突发 8 条在 maxOutgoing=4 下积压；真机 iPhone/AADisplay 均声明
     * 0x7F）。maxLength 保持对端值（=我们的收包上限，勿放大）。
     */
    private fun ownSyncOf(peer: SynchronizationPayload): SynchronizationPayload =
        peer.copy(maxOutgoing = PHONE_DECLARED_MAX_OUTGOING).also {
            declaredMaxOutgoing = PHONE_DECLARED_MAX_OUTGOING
        }

    private fun sendSynchronizationEcho(
        sync: SynchronizationPayload,
        peerSequence: Int,
    ) {
        if (lastEchoPeerSequence == peerSequence) {
            writePacket(ownSyncOf(sync).encode(), lastEchoOwnSequence, CONTROL_SYNCHRONIZE or CONTROL_ACKNOWLEDGEMENT, 0)
            onSynchronizationEchoSent?.invoke()
            return
        }
        val ownSequence = nextSequence(sentSequence).also { sentSequence = it }
        writePacket(ownSyncOf(sync).encode(), ownSequence, CONTROL_SYNCHRONIZE or CONTROL_ACKNOWLEDGEMENT, 0)
        lastEchoPeerSequence = peerSequence
        lastEchoOwnSequence = ownSequence
        onSynchronizationEchoSent?.invoke()
    }

    private fun handleAcknowledgement(
        acknowledgement: Int,
        nowMillis: Long,
    ) {
        completeNegotiationIfPending(nowMillis)
        lastSentAcknowledged = acknowledgement
        val window = (peerSynchronization?.maxOutgoing ?: maxOutgoing) + ACK_SLACK
        unacknowledged.removeAll { sequenceDistance(it.sequence, acknowledgement) !in 1..window }
        retransmitDeadline = unacknowledged.minOfOrNull { it.deadlineMillis }
        drainSendWindow(nowMillis)
    }

    private fun handleData(
        sequence: Int,
        payload: ByteArray,
    ) {
        val distance = sequenceDistance(sequence, lastReceivedInOrder)
        val peerWindow = peerSynchronization?.maxOutgoing ?: maxOutgoing
        if (distance == 0 || distance > peerWindow + ACK_SLACK) {
            sendAcknowledgement() // 重复或过期：重新确认当前序号
            return
        }
        // RFCOMM 为可靠有序流，不会丢包；序号跳变只可能是对端把 ACK/SYN 也计入了序号
        // （各家实现账法不一致）。因此接受任意前进量并推进水位，避免死锁式丢帧。
        lastReceivedInOrder = sequence
        if (pendingEvents.size >= 256) {
            die("event queue overflow")
            return
        }
        if (payload.size >= 6 &&
            payload[0] == 0x40.toByte() &&
            payload[1] == 0x40.toByte() &&
            readU16(payload, 4) == Iap2MessageIds.IDENTIFICATION_INFORMATION
        ) {
            runCatching {
                val params = Iap2Csm.parseParams(payload.copyOfRange(6, payload.size))
                val recvRaw = params.firstOrNull { it.id == 7 }?.value
                if (recvRaw != null && recvRaw.size >= 2 && recvRaw.size % 2 == 0) {
                    peerDeclaredReceiveIds =
                        (0 until recvRaw.size step 2)
                            .map { readU16(recvRaw, it) }
                            .toSet()
                }
                val idParts =
                    listOf(0, 1, 2).mapNotNull { pid ->
                        params
                            .firstOrNull { it.id == pid }
                            ?.value
                            ?.decodeToString()
                            ?.trimEnd('\u0000')
                            ?.takeIf { it.isNotBlank() }
                    }
                val idText = idParts.joinToString(" ")
                val rawAscii = String(payload, Charsets.ISO_8859_1)
                val isLegacyMib3 =
                    idText.contains("MIB3", ignoreCase = true) ||
                        idText.contains("Audi", ignoreCase = true) ||
                        idText.contains("Delphi", ignoreCase = true) ||
                        idText.contains("Alpine", ignoreCase = true) ||
                        idText.contains("Porsche", ignoreCase = true)
                val isGmOrCinemo =
                    rawAscii.contains("Cinemo", ignoreCase = true) ||
                        idText.contains("Buick", ignoreCase = true) ||
                        idText.contains("Cadillac", ignoreCase = true) ||
                        idText.contains("Chevrolet", ignoreCase = true) ||
                        idText.contains("Saic General Motors", ignoreCase = true) ||
                        idText.contains("General Motors", ignoreCase = true) ||
                        idText.contains("E2YB", ignoreCase = true)
                val isCinemoOrNewGen =
                    isGmOrCinemo ||
                        (!isLegacyMib3 && peerDeclaredReceiveIds != null && 0x5702 !in peerDeclaredReceiveIds!!)
                peerPrefers32ByteMfiChallenge = isCinemoOrNewGen
                mfiChallengeUpgraded = false
                if (isCinemoOrNewGen && idText.isNotEmpty()) {
                    MfiLengthMemory.recordSuccess(null, idText, 32)
                    MfiLengthMemory.recordSuccess(null, "$idText tunnel", 32)
                }
            }
        }
        pendingEvents += Event.Control(payload)
        sendAcknowledgement()
    }

    // ---- 发送 ----

    private fun drainSendWindow(nowMillis: Long) {
        if (state != State.NORMAL) return
        while (sendBacklog.isNotEmpty()) {
            val packet = sendBacklog.first()
            val peer = peerSynchronization
            val window = declaredMaxOutgoing
            if (lastSentAcknowledged != null &&
                sequenceDistance(sentSequence, lastSentAcknowledged!!) >= window
            ) {
                return
            }
            sendBacklog.removeFirst()
            sentSequence = nextSequence(sentSequence)
            packet.sequence = sentSequence
            packet.deadlineMillis = nowMillis + retransmissionTimeoutMillis
            writePacket(packet.payload, packet.sequence, CONTROL_ACKNOWLEDGEMENT, controlSessionId())
            if (!packet.awaitAck) continue // 发后不管：不追踪、不重传（见 sendControl 注释）
            if (peer == null || peer.maxRetransmissions > 0) {
                unacknowledged += packet
                retransmitDeadline = packet.deadlineMillis
            } else {
                lastSentAcknowledged = sentSequence
            }
        }
    }

    /** 出向控制消息的会话 ID：采纳了对端表就用其 control ID（Audi=1），否则本表 10。 */
    private fun controlSessionId(): Int = adoptedPeerControlSessionId ?: SESSION_CONTROL

    private fun retransmitDue(nowMillis: Long) {
        val next = unacknowledged.minByOrNull { it.deadlineMillis } ?: return
        next.deadlineMillis = nowMillis + retransmissionTimeoutMillis
        next.retransmissions += 1
        if (next.retransmissions > maxRetransmissions) {
            die("packet ${next.sequence} not acknowledged")
            return
        }
        writePacket(next.payload, next.sequence, CONTROL_ACKNOWLEDGEMENT, controlSessionId())
        retransmitDeadline = unacknowledged.minOfOrNull { it.deadlineMillis }
    }

    private fun sendSynchronization() {
        val payload =
            SynchronizationPayload(
                maxOutgoing = maxOutgoing,
                maxLength = 0xFFFF,
                retransmissionTimeoutMillis = retransmissionTimeoutMillis.toInt().coerceIn(0, 0xFFFF),
                acknowledgementTimeoutMillis = 500,
                maxRetransmissions = maxRetransmissions,
                maxAcknowledgements = 3,
                sessions =
                    listOf(
                        SessionDescriptor(SESSION_CONTROL, 0, 2),
                        SessionDescriptor(SESSION_EA, 2, 1),
                        SessionDescriptor(SESSION_FILE_TRANSFER, 1, 2),
                    ),
            ).encode()
        writePacket(payload, sentSequence, CONTROL_SYNCHRONIZE, 0)
    }

    private fun sendAcknowledgement() {
        writePacket(null, sentSequence, CONTROL_ACKNOWLEDGEMENT, 0)
    }

    private fun writePacket(
        payload: ByteArray?,
        sequence: Int,
        control: Int,
        sessionId: Int,
    ) {
        if (state == State.DEAD) return
        onFrameSent?.invoke(control, sequence, lastReceivedInOrder, sessionId, payload?.size ?: 0)
        val length = payload?.size?.plus(HEADER_BYTES + 1) ?: HEADER_BYTES
        val frame = ByteArray(length)
        frame[0] = 0xFF.toByte()
        frame[1] = 0x5A
        frame[2] = (length ushr 8).toByte()
        frame[3] = length.toByte()
        frame[4] = control.toByte()
        frame[5] = sequence.toByte()
        frame[6] = lastReceivedInOrder.toByte()
        frame[7] = sessionId.toByte()
        var sum = 0
        for (index in 0 until HEADER_BYTES - 1) sum += u8(frame[index])
        frame[HEADER_BYTES - 1] = (-sum and 0xFF).toByte()
        if (payload != null) {
            payload.copyInto(frame, HEADER_BYTES)
            var payloadSum = 0
            payload.forEach { payloadSum += u8(it) }
            frame[frame.size - 1] = (-payloadSum and 0xFF).toByte()
        }
        appendOutput(frame)
    }

    private fun die(reason: String?) {
        if (state == State.DEAD) return
        state = State.DEAD
        markerDeadline = null
        syncDeadline = null
        retransmitDeadline = null
        output.reset()
        pendingEvents.clear()
        sendBacklog.clear()
        pendingEvents += Event.Dead(reason)
    }

    private fun appendOutput(bytes: ByteArray): Boolean {
        if (state == State.DEAD) return false
        output.write(bytes)
        return true
    }

    private class ReceiveBuffer {
        private val bytes = ByteArray(0xFFFF + 8)
        private var head = 0
        private var tail = 0

        val size: Int get() = tail - head

        fun remainingCapacity(): Int {
            compact()
            return bytes.size - tail
        }

        operator fun get(index: Int): Byte = bytes[head + index]

        fun append(
            source: ByteArray,
            offset: Int,
            count: Int,
        ) {
            source.copyInto(bytes, tail, offset, offset + count)
            tail += count
        }

        fun discard(count: Int) {
            head += count
            if (head == tail) {
                head = 0
                tail = 0
            }
        }

        fun peek(count: Int): ByteArray = bytes.copyOfRange(head, head + count)

        fun take(count: Int): ByteArray {
            val out = peek(count)
            discard(count)
            return out
        }

        private fun compact() {
            if (head == 0) return
            if (head < tail) bytes.copyInto(bytes, 0, head, tail)
            tail -= head
            head = 0
        }
    }

    companion object {
        const val SESSION_CONTROL = 10
        const val SESSION_EA = 11
        const val SESSION_FILE_TRANSFER = 12

        /** 会话描述符里的类型字段：0 = 控制会话（xcertplay/extractor/catplay 一致）。 */
        private const val CONTROL_KIND = 0

        val MARKER = byteArrayOf(0xFF.toByte(), 0x55, 0x02, 0x00, 0xEE.toByte(), 0x10)
        const val HEADER_BYTES = 9
        private const val SYNCHRONIZATION_VERSION = 1
        private const val CONTROL_SYNCHRONIZE = 0x80
        private const val CONTROL_ACKNOWLEDGEMENT = 0x40
        private const val CONTROL_EXTENDED_ACKNOWLEDGEMENT = 0x20
        private const val CONTROL_RESET = 0x10
        private const val INITIAL_SEQUENCE = 99
        private const val MARKER_RESEND_MILLIS = 1_000L
        private const val SYNC_RESEND_MILLIS = 500L
        private const val ACK_SLACK = 10

        private fun sequenceDistance(
            sequence: Int,
            previous: Int,
        ): Int = (sequence - previous) and 0xFF

        private fun nextSequence(sequence: Int): Int = (sequence + 1) and 0xFF

        private fun checksumValid(bytes: ByteArray): Boolean {
            var sum = 0
            bytes.forEach { sum += u8(it) }
            return sum and 0xFF == 0
        }

        private fun readU16(
            bytes: ByteArray,
            offset: Int,
        ): Int = (u8(bytes[offset]) shl 8) or u8(bytes[offset + 1])

        private fun writeU16(
            out: ByteArrayOutputStream,
            value: Int,
        ) {
            out.write(value ushr 8)
            out.write(value)
        }

        private fun u8(byte: Byte): Int = byte.toInt() and 0xFF
    }
}
