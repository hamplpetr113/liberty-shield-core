package com.libertyshield.agent.monitors

import android.app.usage.UsageStatsManager
import android.content.Context
import com.libertyshield.agent.GatewayClient
import com.libertyshield.agent.models.SensorEvent
import kotlinx.coroutines.*

// Detects recently foregrounded apps via UsageStatsManager.
// Requires PACKAGE_USAGE_STATS permission granted manually in Settings > Special app access.
// Note: pid is unavailable from UsageStatsManager — reported as 0.
class AppMonitor(
    private val context: Context,
    private val client: GatewayClient,
) {
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val seen = mutableSetOf<String>()

    fun start() {
        scope.launch {
            while (isActive) {
                poll()
                delay(5_000)
            }
        }
    }

    private fun poll() {
        val usm = context.getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
        val now = System.currentTimeMillis()
        val stats = usm.queryUsageStats(UsageStatsManager.INTERVAL_DAILY, now - 10_000, now)
            ?: return
        for (stat in stats) {
            if (stat.lastTimeUsed > now - 10_000 && seen.add(stat.packageName)) {
                client.enqueue(SensorEvent.AppStart(
                    name      = stat.packageName,
                    pid       = 0,
                    parentPid = 0,
                ))
            }
        }
    }

    fun stop() = scope.cancel()
}
