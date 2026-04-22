package com.libertyshield.agent

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle

class LauncherActivity : Activity() {

    companion object {
        private const val REQUEST_VPN = 1
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) {
            @Suppress("DEPRECATION")
            startActivityForResult(vpnIntent, REQUEST_VPN)
        } else {
            startShieldService()
            finish()
        }
    }

    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == REQUEST_VPN && resultCode == RESULT_OK) {
            startShieldService()
        }
        finish()
    }

    private fun startShieldService() {
        startForegroundService(Intent(this, ShieldService::class.java))
    }
}
