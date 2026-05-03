package com.libertyshield.agent

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import com.libertyshield.agent.vpn.ShieldVpnService
import com.libertyshield.agent.vpn.VpnStats
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class RuntimeDashboardActivity : Activity() {

    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())

    // Controls
    private lateinit var vpnStatus:    TextView
    private lateinit var btnStartVpn:  Button
    private lateinit var btnStopVpn:   Button

    // VPN diagnostics
    private lateinit var statVpnLastStopReason: TextView
    private lateinit var statVpnStopCount:      TextView
    private lateinit var statVpnLastStopAge:    TextView
    private lateinit var statVpnLastExcClass:   TextView
    private lateinit var statVpnLastExcMsg:     TextView

    // VPN lifecycle
    private lateinit var statVpnEstablished:       TextView
    private lateinit var statVpnRuntimeRecoveries: TextView
    private lateinit var statVpnTunValid:        TextView
    private lateinit var statVpnReaderRunning:   TextView
    private lateinit var statVpnReaderRestarts:  TextView
    private lateinit var statVpnUptime:          TextView

    // TCP
    private lateinit var statTcpActive:            TextView
    private lateinit var statTcpCreated:           TextView
    private lateinit var statTcpClosed:            TextView
    private lateinit var statTcpQueueDepth:        TextView
    private lateinit var statTcpHighQueueEvents:   TextView
    private lateinit var statTcpConnectAvgMs:      TextView
    private lateinit var statTcpConnectMaxMs:      TextView
    private lateinit var statTcpFirstByteAvgMs:    TextView
    private lateinit var statTcpFirstByteMaxMs:    TextView
    private lateinit var statTcpNoFirstByte:       TextView
    private lateinit var statTcpConnectFailures:   TextView
    private lateinit var statTunWriteQueueDepth:   TextView
    private lateinit var statTcpTunWriteDrops:     TextView

    // DNS
    private lateinit var statDnsCacheHits:       TextView
    private lateinit var statDnsTimeouts:        TextView
    private lateinit var statDnsAvgMs:           TextView

    // UDP
    private lateinit var statUdpSent:            TextView
    private lateinit var statUdpRecv:            TextView
    private lateinit var statUdpErrors:          TextView
    private lateinit var statUdpDrops:           TextView

    // QUIC
    private lateinit var statQuicDropped:        TextView

    // Connection
    private lateinit var statSlowConnects:       TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_runtime_dashboard)
        bindViews()
        startRefreshLoop()
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private fun bindViews() {
        vpnStatus   = findViewById(R.id.vpn_status)
        btnStartVpn = findViewById(R.id.btn_start_vpn)
        btnStopVpn  = findViewById(R.id.btn_stop_vpn)

        btnStartVpn.setOnClickListener {
            startForegroundService(
                Intent(this, ShieldVpnService::class.java)
                    .setAction(ShieldVpnService.ACTION_START)
            )
        }
        btnStopVpn.setOnClickListener {
            startService(
                Intent(this, ShieldVpnService::class.java)
                    .setAction(ShieldVpnService.ACTION_STOP)
            )
        }

        statVpnLastStopReason = findViewById(R.id.stat_vpn_last_stop_reason)
        statVpnStopCount      = findViewById(R.id.stat_vpn_stop_count)
        statVpnLastStopAge    = findViewById(R.id.stat_vpn_last_stop_age)
        statVpnLastExcClass   = findViewById(R.id.stat_vpn_last_exc_class)
        statVpnLastExcMsg     = findViewById(R.id.stat_vpn_last_exc_msg)

        statVpnEstablished       = findViewById(R.id.stat_vpn_established)
        statVpnRuntimeRecoveries = findViewById(R.id.stat_vpn_runtime_recoveries)
        statVpnTunValid       = findViewById(R.id.stat_vpn_tun_valid)
        statVpnReaderRunning  = findViewById(R.id.stat_vpn_reader_running)
        statVpnReaderRestarts = findViewById(R.id.stat_vpn_reader_restarts)
        statVpnUptime         = findViewById(R.id.stat_vpn_uptime)

        statTcpActive            = findViewById(R.id.stat_tcp_active)
        statTcpCreated           = findViewById(R.id.stat_tcp_created)
        statTcpClosed            = findViewById(R.id.stat_tcp_closed)
        statTcpQueueDepth        = findViewById(R.id.stat_tcp_queue_depth)
        statTcpHighQueueEvents   = findViewById(R.id.stat_tcp_high_queue_events)
        statTcpConnectAvgMs      = findViewById(R.id.stat_tcp_connect_avg_ms)
        statTcpConnectMaxMs      = findViewById(R.id.stat_tcp_connect_max_ms)
        statTcpFirstByteAvgMs    = findViewById(R.id.stat_tcp_first_byte_avg_ms)
        statTcpFirstByteMaxMs    = findViewById(R.id.stat_tcp_first_byte_max_ms)
        statTcpNoFirstByte       = findViewById(R.id.stat_tcp_no_first_byte)
        statTcpConnectFailures   = findViewById(R.id.stat_tcp_connect_failures)
        statTunWriteQueueDepth   = findViewById(R.id.stat_tun_write_queue_depth)
        statTcpTunWriteDrops     = findViewById(R.id.stat_tcp_tun_write_drops)

        statDnsCacheHits  = findViewById(R.id.stat_dns_cache_hits)
        statDnsTimeouts   = findViewById(R.id.stat_dns_timeouts)
        statDnsAvgMs      = findViewById(R.id.stat_dns_avg_ms)

        statUdpSent       = findViewById(R.id.stat_udp_sent)
        statUdpRecv       = findViewById(R.id.stat_udp_recv)
        statUdpErrors     = findViewById(R.id.stat_udp_errors)
        statUdpDrops      = findViewById(R.id.stat_udp_drops)

        statQuicDropped   = findViewById(R.id.stat_quic_dropped)
        statSlowConnects  = findViewById(R.id.stat_slow_connects)
    }

    private fun startRefreshLoop() {
        scope.launch {
            while (isActive) {
                updateStats()
                delay(1_000)
            }
        }
    }

    private fun updateStats() {
        val vpnOn = VpnStats.vpnEstablished.get()
        vpnStatus.text      = "VPN status: ${if (vpnOn) "ON" else "OFF"}"
        vpnStatus.setTextColor(if (vpnOn) 0xFF00CC66.toInt() else 0xFFFF4444.toInt())
        btnStartVpn.isEnabled = !vpnOn
        btnStopVpn.isEnabled  = vpnOn

        // VPN diagnostics
        val lastStopTs = VpnStats.vpnLastStopTimestampMs.get()
        val lastStopAgeStr = if (lastStopTs == 0L) "never" else "${(System.currentTimeMillis() - lastStopTs) / 1000}s ago"
        statVpnLastStopReason.text = "  lastStopReason      :  ${VpnStats.vpnLastStopReason.get().ifEmpty { "—" }}"
        statVpnStopCount.text      = "  stopCount           :  ${VpnStats.vpnStopCount.get()}"
        statVpnLastStopAge.text    = "  lastStopAge         :  $lastStopAgeStr"
        statVpnLastExcClass.text   = "  lastExcClass        :  ${VpnStats.vpnLastExceptionClass.get().ifEmpty { "—" }}"
        statVpnLastExcMsg.text     = "  lastExcMsg          :  ${VpnStats.vpnLastExceptionMessage.get().ifEmpty { "—" }}"

        // VPN lifecycle
        val startMs = VpnStats.vpnStartTimestampMs.get()
        val uptimeStr = if (startMs == 0L) "not started"
                        else "${(System.currentTimeMillis() - startMs) / 1000}s"
        statVpnEstablished.text       = "  vpnEstablished      :  ${VpnStats.vpnEstablished.get()}"
        statVpnRuntimeRecoveries.text = "  runtimeRecoveries   :  ${VpnStats.runtimeRecoveries.get()}"
        statVpnTunValid.text       = "  tunFdValid          :  ${VpnStats.tunFdValid.get()}"
        statVpnReaderRunning.text  = "  packetReaderRunning :  ${VpnStats.packetReaderRunning.get()}"
        statVpnReaderRestarts.text = "  readerRestarts      :  ${VpnStats.packetReaderRestarts.get()}"
        statVpnUptime.text         = "  uptime              :  $uptimeStr"

        // TCP
        val dnsCount = VpnStats.dnsLatencyCount.get()
        val dnsAvg   = if (dnsCount > 0) "${VpnStats.dnsTotalLatencyMs.get() / dnsCount} ms" else "n/a"

        val connCount = VpnStats.tcpConnectCount.get()
        val connAvg   = if (connCount > 0) "${VpnStats.tcpConnectTotalMs.get() / connCount} ms" else "n/a"
        val fbCount   = VpnStats.tcpFirstByteCount.get()
        val fbAvg     = if (fbCount > 0) "${VpnStats.tcpFirstByteTotalMs.get() / fbCount} ms" else "n/a"

        statTcpActive.text            = "  activeTcpSessions   :  ${VpnStats.tcpSessionsActive.get()}"
        statTcpCreated.text           = "  tcpCreated          :  ${VpnStats.tcpSessionsCreated.get()}"
        statTcpClosed.text            = "  tcpClosed           :  ${VpnStats.tcpSessionsClosed.get()}"
        statTcpQueueDepth.text        = "  tcpQueueMaxDepth    :  ${VpnStats.tcpQueueMaxDepth.get()}"
        statTcpHighQueueEvents.text   = "  tcpHighQueueEvents  :  ${VpnStats.tcpHighQueueEvents.get()}"
        statTcpConnectAvgMs.text      = "  tcpConnectAvgMs     :  $connAvg"
        statTcpConnectMaxMs.text      = "  tcpConnectMaxMs     :  ${VpnStats.tcpConnectMaxMs.get()} ms"
        statTcpFirstByteAvgMs.text    = "  tcpFirstByteAvgMs   :  $fbAvg"
        statTcpFirstByteMaxMs.text    = "  tcpFirstByteMaxMs   :  ${VpnStats.tcpFirstByteMaxMs.get()} ms"
        statTcpNoFirstByte.text       = "  tcpNoFirstByte      :  ${VpnStats.tcpSessionsNoFirstByte.get()}"
        statTcpConnectFailures.text   = "  tcpConnectFailures  :  ${VpnStats.tcpConnectFailures.get()}"
        statTunWriteQueueDepth.text   = "  tunWriteQueueDepth  :  ${VpnStats.tunWriteQueueDepth.get()}"
        statTcpTunWriteDrops.text     = "  tcpTunWriteDrops    :  ${VpnStats.tcpTunWriteDrops.get()}"

        // DNS
        statDnsCacheHits.text  = "  dnsCacheHits        :  ${VpnStats.dnsCacheHits.get()}"
        statDnsTimeouts.text   = "  dnsTimeouts         :  ${VpnStats.dnsTimeouts.get()}"
        statDnsAvgMs.text      = "  dnsAvgMs            :  $dnsAvg"

        // UDP
        statUdpSent.text       = "  udpRequestsSent     :  ${VpnStats.udpRequestsSent.get()}"
        statUdpRecv.text       = "  udpResponsesRecv    :  ${VpnStats.udpResponsesRecv.get()}"
        statUdpErrors.text     = "  udpErrors           :  ${VpnStats.udpErrors.get()}"
        statUdpDrops.text      = "  udpConcurrencyDrops :  ${VpnStats.udpConcurrencyDrops.get()}"

        // QUIC
        statQuicDropped.text   = "  quicDropped         :  ${VpnStats.quicDropped.get()}"

        // Connection
        statSlowConnects.text  = "  tcpSlowConnects     :  ${VpnStats.tcpSlowConnects.get()}"
    }
}
