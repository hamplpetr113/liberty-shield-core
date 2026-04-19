package com.libertyshield.agent

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import com.libertyshield.agent.vpn.ShieldVpnService

// Trampoline Activity — Services cannot show the system VPN consent dialog.
// Callers start this Activity; it shows the dialog and, on approval, starts ShieldVpnService.
class VpnPermissionActivity : Activity() {

    companion object {
        private const val REQUEST_VPN = 1
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val intent = VpnService.prepare(this)
        if (intent != null) {
            startActivityForResult(intent, REQUEST_VPN)
        } else {
            // Permission already granted — start service immediately
            onPermissionGranted()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == REQUEST_VPN) {
            if (resultCode == RESULT_OK) {
                onPermissionGranted()
            }
            // On denial: do nothing — VPN stays off
        }
        finish()
    }

    private fun onPermissionGranted() {
        val intent = Intent(this, ShieldVpnService::class.java)
            .setAction(ShieldVpnService.ACTION_START)
        startService(intent)
        finish()
    }
}
