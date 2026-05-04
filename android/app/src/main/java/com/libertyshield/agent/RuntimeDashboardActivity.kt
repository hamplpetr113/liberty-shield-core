package com.libertyshield.agent

import android.app.Activity
import android.content.Intent
import android.net.VpnService
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

    companion object {
        private const val REQUEST_VPN = 2001
    }

    // Controls
    private lateinit var vpnStatus:      TextView
    private lateinit var btnStartVpn:    Button
    private lateinit var btnStopVpn:     Button
    private lateinit var btnBatterySetup: Button

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
    private lateinit var statTcpConnectFailures:         TextView
    private lateinit var statTcpClientPayloadPackets:    TextView
    private lateinit var statTcpClientPayloadBytes:      TextView
    private lateinit var statTcpPayloadToFbAvgMs:        TextView
    private lateinit var statTcpPayloadToFbMaxMs:        TextView
    private lateinit var statTcpServerReadToTunAvgMs:    TextView
    private lateinit var statTcpServerReadToTunMaxMs:    TextView
    private lateinit var statTunWriteControlDepth:    TextView
    private lateinit var statTunWriteControlMaxDepth: TextView
    private lateinit var statTunWriteDataDepth:       TextView
    private lateinit var statTunWriteDataMaxDepth:    TextView
    private lateinit var statTunWriteControlDrops:    TextView
    private lateinit var statTunWriteDataDrops:       TextView
    private lateinit var statTunDataBackpressureWaits: TextView
    private lateinit var statTunDataBackpressureMs:    TextView
    private lateinit var statTcpExpired:            TextView
    private lateinit var statTcpExpiredNoFirstByte: TextView
    private lateinit var statTcpExpiredIdle:        TextView
    private lateinit var statTcpExpiredLifetime:    TextView

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

    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == REQUEST_VPN && resultCode == RESULT_OK) {
            startServices()
        }
        // Denied: do nothing — button re-enables naturally on the next updateStats() tick.
    }

    // Mirrors LauncherActivity.startServices(): start VPN and telemetry independently so
    // VPN startup does not depend on ShieldService initialising without error.
    private fun startServices() {
        startForegroundService(
            Intent(this, ShieldVpnService::class.java)
                .setAction(ShieldVpnService.ACTION_START)
        )
        startForegroundService(Intent(this, ShieldService::class.java))
    }

    // Must call VpnService.prepare() before starting the VPN service; without it Android's
    // VpnService.Builder.establish() returns null even if permission was granted before,
    // and the VPN silently fails. LauncherActivity does this correctly on every start;
    // the dashboard previously skipped it, which is why Start worked from LauncherActivity
    // but not from the dashboard after a Stop.
    private fun startVpnFromDashboard() {
        btnStartVpn.isEnabled = false  // immediate feedback; re-enabled by updateStats() if start fails
        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) {
            @Suppress("DEPRECATION")
            startActivityForResult(vpnIntent, REQUEST_VPN)
        } else {
            startServices()
        }
    }

    private fun bindViews() {
        vpnStatus       = findViewById(R.id.vpn_status)
        btnStartVpn     = findViewById(R.id.btn_start_vpn)
        btnStopVpn      = findViewById(R.id.btn_stop_vpn)
        btnBatterySetup = findViewById(R.id.btn_battery_setup)

        btnStartVpn.setOnClickListener { startVpnFromDashboard() }
        btnStopVpn.setOnClickListener {
            startService(
                Intent(this, ShieldVpnService::class.java)
                    .setAction(ShieldVpnService.ACTION_STOP)
            )
        }
        btnBatterySetup.setOnClickListener {
            startActivity(Intent(this, BatterySetupActivity::class.java))
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
        statTcpConnectFailures          = findViewById(R.id.stat_tcp_connect_failures)
        statTcpClientPayloadPackets     = findViewById(R.id.stat_tcp_client_payload_packets)
        statTcpClientPayloadBytes       = findViewById(R.id.stat_tcp_client_payload_bytes)
        statTcpPayloadToFbAvgMs         = findViewById(R.id.stat_tcp_payload_to_fb_avg_ms)
        statTcpPayloadToFbMaxMs         = findViewById(R.id.stat_tcp_payload_to_fb_max_ms)
        statTcpServerReadToTunAvgMs     = findViewById(R.id.stat_tcp_server_read_to_tun_avg_ms)
        statTcpServerReadToTunMaxMs     = findViewById(R.id.stat_tcp_server_read_to_tun_max_ms)
        statTunWriteControlDepth   = findViewById(R.id.stat_tun_write_control_depth)
        statTunWriteControlMaxDepth= findViewById(R.id.stat_tun_write_control_max_depth)
        statTunWriteDataDepth      = findViewById(R.id.stat_tun_write_data_depth)
        statTunWriteDataMaxDepth   = findViewById(R.id.stat_tun_write_data_max_depth)
        statTunWriteControlDrops   = findViewById(R.id.stat_tun_write_control_drops)
        statTunWriteDataDrops      = findViewById(R.id.stat_tun_write_data_drops)
        statTunDataBackpressureWaits = findViewById(R.id.stat_tun_data_backpressure_waits)
        statTunDataBackpressureMs    = findViewById(R.id.stat_tun_data_backpressure_ms)
        statTcpExpired            = findViewById(R.id.stat_tcp_expired)
        statTcpExpiredNoFirstByte = findViewById(R.id.stat_tcp_expired_no_first_byte)
        statTcpExpiredIdle        = findViewById(R.id.stat_tcp_expired_idle)
        statTcpExpiredLifetime    = findViewById(R.id.stat_tcp_expired_lifetime)

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
        statTcpConnectFailures.text     = "  tcpConnectFailures   :  ${VpnStats.tcpConnectFailures.get()}"

        val p2fbCount = VpnStats.tcpFirstClientPayloadToFirstByteCount.get()
        val p2fbAvg   = if (p2fbCount > 0) "${VpnStats.tcpFirstClientPayloadToFirstByteTotalMs.get() / p2fbCount} ms" else "n/a"
        val srteCount = VpnStats.tcpServerReadToTunEnqueueCount.get()
        val srteAvg   = if (srteCount > 0) "${VpnStats.tcpServerReadToTunEnqueueTotalMs.get() / srteCount} ms" else "n/a"
        statTcpClientPayloadPackets.text  = "  tcpClientPkts       :  ${VpnStats.tcpClientPayloadPackets.get()}"
        statTcpClientPayloadBytes.text    = "  tcpClientBytes       :  ${VpnStats.tcpClientPayloadBytes.get()}"
        statTcpPayloadToFbAvgMs.text      = "  tcpP2FBAvgMs        :  $p2fbAvg"
        statTcpPayloadToFbMaxMs.text      = "  tcpP2FBMaxMs        :  ${VpnStats.tcpFirstClientPayloadToFirstByteMaxMs.get()} ms"
        statTcpServerReadToTunAvgMs.text  = "  tcpSRTEAvgMs        :  $srteAvg"
        statTcpServerReadToTunMaxMs.text  = "  tcpSRTEMaxMs        :  ${VpnStats.tcpServerReadToTunEnqueueMaxMs.get()} ms"

        statTunWriteControlDepth.text    = "  tunCtrlDepth        :  ${VpnStats.tunWriteControlDepth.get()}"
        statTunWriteControlMaxDepth.text = "  tunCtrlMaxDepth     :  ${VpnStats.tunWriteControlMaxDepth.get()}"
        statTunWriteDataDepth.text       = "  tunDataDepth        :  ${VpnStats.tunWriteDataDepth.get()}"
        statTunWriteDataMaxDepth.text    = "  tunDataMaxDepth     :  ${VpnStats.tunWriteDataMaxDepth.get()}"
        statTunWriteControlDrops.text    = "  tunCtrlDrops        :  ${VpnStats.tunWriteControlDrops.get()}"
        statTunWriteDataDrops.text       = "  tunDataDrops        :  ${VpnStats.tunWriteDataDrops.get()}"
        statTunDataBackpressureWaits.text = "  tunDataBpWaits      :  ${VpnStats.tunDataBackpressureWaits.get()}"
        statTunDataBackpressureMs.text    = "  tunDataBpMs         :  ${VpnStats.tunDataBackpressureMs.get()}"
        statTcpExpired.text            = "  tcpExpired          :  ${VpnStats.tcpSessionsExpired.get()}"
        statTcpExpiredNoFirstByte.text = "  expNoFirstByte      :  ${VpnStats.tcpSessionsExpiredNoFirstByte.get()}"
        statTcpExpiredIdle.text        = "  expIdle             :  ${VpnStats.tcpSessionsExpiredIdle.get()}"
        statTcpExpiredLifetime.text    = "  expLifetime         :  ${VpnStats.tcpSessionsExpiredLifetime.get()}"

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
