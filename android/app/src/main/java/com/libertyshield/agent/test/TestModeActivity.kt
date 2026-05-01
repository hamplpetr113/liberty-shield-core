package com.libertyshield.agent.test

import android.app.Activity
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.libertyshield.agent.ffi.RuntimeBridge
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Sprint 206 — Minimal debug Activity for the two-phone test.
 *
 * No XML layout — UI is built programmatically to avoid adding res files.
 * Saves/restores peer config via [PeerConfigStore].
 *
 * Flow:
 *   1. Fill in peer IP / ports / phone seed.
 *   2. Tap "Start Test" — launches [TestModeController].
 *   3. Tap "Send Ping" to initiate a round-trip.
 *   4. HUD updates every 2 s while running.
 *   5. Tap "Stop Test" or press back to tear down.
 *
 * TEST MODE ONLY — NOT FOR PRODUCTION USE.
 */
class TestModeActivity : Activity() {

    private var controller: TestModeController? = null
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())

    private lateinit var hudView: TextView
    private lateinit var peerIpInput: EditText
    private lateinit var peerPortInput: EditText
    private lateinit var localPortInput: EditText
    private lateinit var phoneSeedInput: EditText
    private lateinit var startBtn: Button
    private lateinit var stopBtn: Button
    private lateinit var pingBtn: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        buildUi()
        restoreConfig()
        LibertyLogger.status("TestModeActivity created")
    }

    override fun onDestroy() {
        stopTest()
        scope.cancel()
        super.onDestroy()
    }

    private fun buildUi() {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 48, 24, 24)
        }

        root.addView(TextView(this).apply {
            text = "[TEST MODE — NOT FOR PRODUCTION USE]"
            textSize = 11f
        })

        peerIpInput = EditText(this).apply { hint = "Peer IP  (e.g. 192.168.1.100)" }
        peerPortInput = EditText(this).apply { hint = "Peer UDP port  (e.g. 9001)" }
        localPortInput = EditText(this).apply { hint = "Local UDP port  (e.g. 9000)" }
        phoneSeedInput = EditText(this).apply { hint = "Phone seed  (10 = Phone A, 11 = Phone B)" }

        listOf(peerIpInput, peerPortInput, localPortInput, phoneSeedInput).forEach { root.addView(it) }

        val btnRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        startBtn = Button(this).apply { text = "Start"; setOnClickListener { startTest() } }
        stopBtn = Button(this).apply { text = "Stop"; setOnClickListener { stopTest() }; isEnabled = false }
        pingBtn = Button(this).apply { text = "Ping"; setOnClickListener { controller?.sendPing() }; isEnabled = false }
        listOf(startBtn, stopBtn, pingBtn).forEach { btnRow.addView(it) }
        root.addView(btnRow)

        hudView = TextView(this).apply { textSize = 11f; text = "=== LIBERTY TEST HUD ===" }
        val scroll = ScrollView(this)
        scroll.addView(hudView)
        root.addView(scroll)

        setContentView(root)
    }

    private fun restoreConfig() {
        val cfg = PeerConfigStore(this).load() ?: return
        peerIpInput.setText(cfg.peerIp)
        peerPortInput.setText(cfg.peerUdpPort.toString())
        localPortInput.setText(cfg.localUdpPort.toString())
        phoneSeedInput.setText(cfg.localNodeSeed.toInt().toString())
    }

    private fun startTest() {
        val peerIp = peerIpInput.text.toString().ifBlank { "192.168.1.100" }
        val peerPort = peerPortInput.text.toString().toIntOrNull() ?: 9001
        val localPort = localPortInput.text.toString().toIntOrNull() ?: 9000
        val seedInt = phoneSeedInput.text.toString().toIntOrNull() ?: 10
        val localSeed = seedInt.toByte()
        val peerSeed = if (localSeed == TestIdentity.SEED_PHONE_A) TestIdentity.SEED_PHONE_B
                       else TestIdentity.SEED_PHONE_A
        val config = PeerConfig(
            localNodeSeed = localSeed,
            peerNodeSeed = peerSeed,
            localUdpPort = localPort,
            peerIp = peerIp,
            peerUdpPort = peerPort,
        )
        PeerConfigStore(this).save(config)

        val ctrl = TestModeController(RuntimeBridge(), config)
        controller = ctrl

        scope.launch {
            setButtonsRunning(false)
            val ok = withContext(Dispatchers.IO) { ctrl.start() }
            if (ok) {
                setButtonsRunning(true)
                launchHudRefresh(ctrl)
            } else {
                controller = null
                hudView.text = "Start failed — check logcat (adb logcat -s LIBERTY_TEST)"
                setButtonsRunning(false)
                startBtn.isEnabled = true
            }
        }
    }

    private fun stopTest() {
        val ctrl = controller ?: return
        controller = null
        scope.launch(Dispatchers.IO) { ctrl.stop() }
        setButtonsRunning(false)
        startBtn.isEnabled = true
    }

    private fun setButtonsRunning(running: Boolean) {
        startBtn.isEnabled = !running
        stopBtn.isEnabled = running
        pingBtn.isEnabled = running
    }

    private fun launchHudRefresh(ctrl: TestModeController) {
        scope.launch {
            while (isActive && controller == ctrl) {
                delay(2_000)
                val s = withContext(Dispatchers.IO) { ctrl.hud.snapshot() }
                hudView.text = ctrl.hud.format(s)
            }
        }
    }
}
