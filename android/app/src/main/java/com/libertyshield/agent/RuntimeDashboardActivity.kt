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

    private lateinit var statTcpActive:    TextView
    private lateinit var statTcpCreated:   TextView
    private lateinit var statTcpClosed:    TextView
    private lateinit var statTcpQueueDepth:TextView
    private lateinit var statDnsCacheHits: TextView
    private lateinit var statDnsTimeouts:  TextView
    private lateinit var statDnsAvgMs:     TextView
    private lateinit var statUdpSent:      TextView
    private lateinit var statUdpRecv:      TextView
    private lateinit var statUdpErrors:    TextView
    private lateinit var statUdpDrops:     TextView
    private lateinit var statQuicDropped:  TextView
    private lateinit var statSlowConnects: TextView

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
        statTcpActive     = findViewById(R.id.stat_tcp_active)
        statTcpCreated    = findViewById(R.id.stat_tcp_created)
        statTcpClosed     = findViewById(R.id.stat_tcp_closed)
        statTcpQueueDepth = findViewById(R.id.stat_tcp_queue_depth)
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
        val dnsCount = VpnStats.dnsLatencyCount.get()
        val dnsAvg   = if (dnsCount > 0) "${VpnStats.dnsTotalLatencyMs.get() / dnsCount} ms" else "n/a"

        statTcpActive.text     = "  activeTcpSessions  :  ${VpnStats.tcpSessionsActive.get()}"
        statTcpCreated.text    = "  tcpCreated         :  ${VpnStats.tcpSessionsCreated.get()}"
        statTcpClosed.text     = "  tcpClosed          :  ${VpnStats.tcpSessionsClosed.get()}"
        statTcpQueueDepth.text = "  tcpQueueMaxDepth   :  ${VpnStats.tcpQueueMaxDepth.get()}"

        statDnsCacheHits.text  = "  dnsCacheHits       :  ${VpnStats.dnsCacheHits.get()}"
        statDnsTimeouts.text   = "  dnsTimeouts        :  ${VpnStats.dnsTimeouts.get()}"
        statDnsAvgMs.text      = "  dnsAvgMs           :  $dnsAvg"

        statUdpSent.text       = "  udpRequestsSent    :  ${VpnStats.udpRequestsSent.get()}"
        statUdpRecv.text       = "  udpResponsesRecv   :  ${VpnStats.udpResponsesRecv.get()}"
        statUdpErrors.text     = "  udpErrors          :  ${VpnStats.udpErrors.get()}"
        statUdpDrops.text      = "  udpConcurrencyDrops:  ${VpnStats.udpConcurrencyDrops.get()}"

        statQuicDropped.text   = "  quicDropped        :  ${VpnStats.quicDropped.get()}"

        statSlowConnects.text  = "  tcpSlowConnects    :  ${VpnStats.tcpSlowConnects.get()}"
    }
}
