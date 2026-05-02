package com.libertyshield.agent

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

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
            startShieldService()
        }
    }

    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == REQUEST_VPN && resultCode == RESULT_OK) {
            startShieldService()
        }
    }

    private fun startShieldService() {
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
            text = "VPN protection active"
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
