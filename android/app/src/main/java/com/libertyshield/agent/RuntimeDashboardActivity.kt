package com.libertyshield.agent

import android.app.Activity
import android.os.Bundle
import android.widget.TextView
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

    // VPN lifecycle
    private lateinit var statVpnEstablished:    TextView
    private lateinit var statVpnTunValid:        TextView
    private lateinit var statVpnReaderRunning:   TextView
    private lateinit var statVpnReaderRestarts:  TextView
    private lateinit var statVpnUptime:          TextView

    // TCP
    private lateinit var statTcpActive:          TextView
    private lateinit var statTcpCreated:         TextView
    private lateinit var statTcpClosed:          TextView
    private lateinit var statTcpQueueDepth:      TextView
    private lateinit var statTcpHighQueueEvents: TextView

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
        statVpnEstablished    = findViewById(R.id.stat_vpn_established)
        statVpnTunValid       = findViewById(R.id.stat_vpn_tun_valid)
        statVpnReaderRunning  = findViewById(R.id.stat_vpn_reader_running)
        statVpnReaderRestarts = findViewById(R.id.stat_vpn_reader_restarts)
        statVpnUptime         = findViewById(R.id.stat_vpn_uptime)

        statTcpActive          = findViewById(R.id.stat_tcp_active)
        statTcpCreated         = findViewById(R.id.stat_tcp_created)
        statTcpClosed          = findViewById(R.id.stat_tcp_closed)
        statTcpQueueDepth      = findViewById(R.id.stat_tcp_queue_depth)
        statTcpHighQueueEvents = findViewById(R.id.stat_tcp_high_queue_events)

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
        // VPN lifecycle
        val startMs = VpnStats.vpnStartTimestampMs.get()
        val uptimeStr = if (startMs == 0L) "not started"
                        else "${(System.currentTimeMillis() - startMs) / 1000}s"
        statVpnEstablished.text    = "  vpnEstablished      :  ${VpnStats.vpnEstablished.get()}"
        statVpnTunValid.text       = "  tunFdValid          :  ${VpnStats.tunFdValid.get()}"
        statVpnReaderRunning.text  = "  packetReaderRunning :  ${VpnStats.packetReaderRunning.get()}"
        statVpnReaderRestarts.text = "  readerRestarts      :  ${VpnStats.packetReaderRestarts.get()}"
        statVpnUptime.text         = "  uptime              :  $uptimeStr"

        // TCP
        val dnsCount = VpnStats.dnsLatencyCount.get()
        val dnsAvg   = if (dnsCount > 0) "${VpnStats.dnsTotalLatencyMs.get() / dnsCount} ms" else "n/a"

        statTcpActive.text          = "  activeTcpSessions   :  ${VpnStats.tcpSessionsActive.get()}"
        statTcpCreated.text         = "  tcpCreated          :  ${VpnStats.tcpSessionsCreated.get()}"
        statTcpClosed.text          = "  tcpClosed           :  ${VpnStats.tcpSessionsClosed.get()}"
        statTcpQueueDepth.text      = "  tcpQueueMaxDepth    :  ${VpnStats.tcpQueueMaxDepth.get()}"
        statTcpHighQueueEvents.text = "  tcpHighQueueEvents  :  ${VpnStats.tcpHighQueueEvents.get()}"

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
