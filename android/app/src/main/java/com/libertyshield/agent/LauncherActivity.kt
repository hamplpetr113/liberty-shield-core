package com.libertyshield.agent

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import com.libertyshield.agent.vpn.ShieldVpnService

class LauncherActivity : Activity() {

    companion object {
        private const val REQUEST_VPN = 1
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        buildUi()
        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) {
            @Suppress("DEPRECATION")
            startActivityForResult(vpnIntent, REQUEST_VPN)
        } else {
            startServices()
        }
    }

    // Called on every return to the foreground. Restarts services if battery management killed
    // them while the activity was backgrounded. startForegroundService on an already-running
    // service is a no-op at the engine level (onStartCommand is called but onCreate is not).
    override fun onResume() {
        super.onResume()
        if (VpnService.prepare(this) == null) {
            startServices()
        }
    }

    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == REQUEST_VPN && resultCode == RESULT_OK) {
            startServices()
        }
    }

    // Start VPN directly from LauncherActivity so VPN startup is independent of ShieldService.
    // Previously: LauncherActivity → ShieldService → ShieldVpnService (VPN failed silently if
    // ShieldService initialization threw before reaching startVpnTelemetry()).
    // Now: LauncherActivity starts both independently; ShieldService telemetry is optional.
    private fun startServices() {
        startForegroundService(
            Intent(this, ShieldVpnService::class.java)
                .setAction(ShieldVpnService.ACTION_START)
        )
        startForegroundService(Intent(this, ShieldService::class.java))
    }

    private fun buildUi() {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 80, 48, 48)
        }
        root.addView(TextView(this).apply {
            text = "Liberty Shield"
            textSize = 26f
        })
        root.addView(TextView(this).apply {
            text = "VPN relay starting…"
            textSize = 14f
            setPadding(0, 8, 0, 48)
        })
        root.addView(Button(this).apply {
            text = "Runtime stats"
            setOnClickListener {
                startActivity(Intent(this@LauncherActivity, RuntimeDashboardActivity::class.java))
            }
        })
        setContentView(root)
    }
}
