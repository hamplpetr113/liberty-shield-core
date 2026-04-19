package com.libertyshield.agent.monitors

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorEvent as HardwareSensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import com.libertyshield.agent.GatewayClient
import com.libertyshield.agent.models.SensorEvent

// Reports motion/environment sensor activity from this process only.
// Note: Android does not expose which app is reading a given sensor.
// Reporting here is always attributed to this agent's own packageName.
// Camera and microphone access detection requires AppOpsManager (Android 12+) —
// not implemented in this scaffold.
class SensorMonitor(
    private val context: Context,
    private val client: GatewayClient,
) {
    private val sm = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
    private val listeners = mutableListOf<SensorEventListener>()

    private val watched = listOf(
        Sensor.TYPE_ACCELEROMETER to "accelerometer",
        Sensor.TYPE_GYROSCOPE     to "gyroscope",
    )

    fun start() {
        for ((type, sensorName) in watched) {
            val sensor = sm.getDefaultSensor(type) ?: continue
            var lastReported = 0L
            val listener = object : SensorEventListener {
                override fun onSensorChanged(e: HardwareSensorEvent) {
                    val now = System.currentTimeMillis()
                    if (now - lastReported > 30_000) {
                        lastReported = now
                        client.enqueue(SensorEvent.SensorAccess(
                            sensor  = sensorName,
                            pid     = 0,
                            appName = context.packageName,
                        ))
                    }
                }
                override fun onAccuracyChanged(s: Sensor, accuracy: Int) {}
            }
            sm.registerListener(listener, sensor, SensorManager.SENSOR_DELAY_NORMAL)
            listeners.add(listener)
        }
    }

    fun stop() {
        listeners.forEach { sm.unregisterListener(it) }
        listeners.clear()
    }
}
