package com.libertyshield.agent.models

import org.json.JSONObject

sealed class SensorEvent {
    abstract fun toJson(deviceId: String): String

    data class AppStart(
        val name: String,
        val pid: Int,
        val parentPid: Int,
    ) : SensorEvent() {
        override fun toJson(deviceId: String) = JSONObject()
            .put("device_id", deviceId)
            .put("event", JSONObject()
                .put("type", "app_start")
                .put("name", name)
                .put("pid", pid)
                .put("parent_pid", parentPid))
            .toString()
    }

    data class NetworkConnection(
        val remoteIp: String,
        val remotePort: Int,
        val pid: Int?,
    ) : SensorEvent() {
        override fun toJson(deviceId: String) = JSONObject()
            .put("device_id", deviceId)
            .put("event", JSONObject()
                .put("type", "network_connection")
                .put("remote_ip", remoteIp)
                .put("remote_port", remotePort)
                .apply { pid?.let { put("pid", it) } })
            .toString()
    }

    data class SensorAccess(
        val sensor: String,
        val pid: Int,
        val appName: String,
    ) : SensorEvent() {
        override fun toJson(deviceId: String) = JSONObject()
            .put("device_id", deviceId)
            .put("event", JSONObject()
                .put("type", "sensor_access")
                .put("sensor", sensor)
                .put("pid", pid)
                .put("app_name", appName))
            .toString()
    }

    data class PermissionGranted(
        val permission: String,
        val pid: Int,
        val appName: String,
    ) : SensorEvent() {
        override fun toJson(deviceId: String) = JSONObject()
            .put("device_id", deviceId)
            .put("event", JSONObject()
                .put("type", "permission_granted")
                .put("permission", permission)
                .put("pid", pid)
                .put("app_name", appName))
            .toString()
    }

    object Ipv6Connection : SensorEvent() {
        override fun toJson(deviceId: String) = JSONObject()
            .put("device_id", deviceId)
            .put("event", JSONObject().put("type", "ipv6_connection"))
            .toString()
    }
}
