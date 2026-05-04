package com.libertyshield.agent

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

class BatterySetupActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(buildUi())
    }

    private fun buildUi(): ScrollView {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 48, 48, 64)
            setBackgroundColor(Color.BLACK)
        }

        root.addView(label("Battery / Always-on Setup", 20f, bold = true, bottomPad = 16))

        root.addView(label(
            "Android battery restrictions can silently stop the VPN service, " +
            "causing the key icon to disappear and traffic to leave unprotected. " +
            "Complete the steps below to keep Liberty Shield running reliably in the background.",
            13f, color = 0xFFCCCCCC.toInt(), bottomPad = 24,
        ))

        root.addView(label("Required steps", 14f, bold = true, bottomPad = 8))

        val steps = listOf(
            "1.  Disable battery optimization\n" +
            "    App Settings → Battery → No restrictions (or Unrestricted).\n" +
            "    This prevents Android from killing the VPN service while idle.",

            "2.  Allow background activity\n" +
            "    App Settings → Battery → Allow background activity.\n" +
            "    Required on Samsung and some other OEMs.",

            "3.  Enable autostart (OEM-specific)\n" +
            "    Xiaomi: Security → Autostart → Liberty Shield Agent ON.\n" +
            "    Huawei/Honor: App Launch → Liberty Shield Agent → Manage manually → Autostart ON.\n" +
            "    Other OEMs: look for a similar setting in system Security or App settings.",

            "4.  Enable Always-on VPN  (recommended)\n" +
            "    VPN Settings → find Liberty Shield Agent → toggle Always-on VPN.\n" +
            "    Android will restart the VPN automatically if it stops.",

            "5.  Keep \"Block connections without VPN\" OFF\n" +
            "    Leave this disabled for now. Enabling it blocks all internet while\n" +
            "    the VPN is restarting, which can cause app connectivity errors.",
        )

        for (step in steps) {
            root.addView(label(step, 12f, color = 0xFFDDDDDD.toInt(), bottomPad = 14))
        }

        root.addView(label("Open settings screens", 14f, bold = true, bottomPad = 8, topPad = 8))

        root.addView(btn("Open App Settings")          { openAppSettings() })
        root.addView(btn("Open Battery Optimization")  { openBatteryOptimization() })
        root.addView(btn("Open VPN Settings")          { openVpnSettings() })
        root.addView(btn("Back")                       { finish() })

        return ScrollView(this).apply {
            setBackgroundColor(Color.BLACK)
            addView(root)
        }
    }

    // ── Settings launchers ────────────────────────────────────────────────────

    private fun openAppSettings() {
        startActivity(
            Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                .setData(Uri.fromParts("package", packageName, null))
        )
    }

    private fun openBatteryOptimization() {
        // ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS opens the full battery optimisation list;
        // no extra permission required. The user can find and exempt Liberty Shield from there.
        try {
            startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
        } catch (_: Exception) {
            openAppSettings()   // safe fallback on devices that don't expose the page
        }
    }

    private fun openVpnSettings() {
        // ACTION_VPN_SETTINGS (API 24) shows the VPN list where Always-on VPN can be toggled.
        try {
            startActivity(Intent(Settings.ACTION_VPN_SETTINGS))
        } catch (_: Exception) {
            startActivity(Intent(Settings.ACTION_WIRELESS_SETTINGS))
        }
    }

    // ── UI helpers ────────────────────────────────────────────────────────────

    private fun label(
        text: String,
        size: Float,
        bold: Boolean = false,
        color: Int = Color.WHITE,
        bottomPad: Int = 0,
        topPad: Int = 0,
    ) = TextView(this).apply {
        this.text = text
        textSize  = size
        setTextColor(color)
        typeface  = if (bold) Typeface.DEFAULT_BOLD else Typeface.MONOSPACE
        setPadding(0, topPad.dp, 0, bottomPad.dp)
    }

    private fun btn(text: String, onClick: () -> Unit) = Button(this).apply {
        this.text = text
        setOnClickListener { onClick() }
        val v = 6.dp
        setPadding(0, v, 0, v)
    }

    private val Int.dp: Int get() = (this * resources.displayMetrics.density).toInt()
}
