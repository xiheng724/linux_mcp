# OpenClaw 外部 App 接入流程



### Step 1: 外部 App 连接 Gateway

`[Phone App] -- WebSocket --> [OpenClaw Gateway]`

- WebSocket: 建立一次 TCP 连接后持续复用该连接，无需反复握手，Full-Duplex，传递message

```
ws = WebSocket("ws://gateway:port")
ws.connect()
```



### Step 2: 注册能力

建立连接后，App 会发送：

```
{
  "type": "register",
  "capabilities": [
    {
      "name": "camera.takePhoto",
      "params": { "resolution": "string" }
    }
  ]
}
```



### Step 3: Gateway 建立映射

`camera.takePhoto → node_123`



### Step 4: 用户发起调用

`node.invoke("camera.takePhoto", {"resolution": "1080p"})`



### Step 5: Gateway 转发请求

`Gateway --> WebSocket --> App`

Gateway 发送信息：

```
{
  "type": "invoke",
  "method": "camera.takePhoto",
  "params": { "resolution": "1080p" },
  "request_id": "abc123"
}
```



### Step 6: 外部 App 执行

`photo = take_photo()`



### Step 7: 返回结果

```
{
  "type": "result",
  "request_id": "abc123",
  "data": "image_base64..."
}
```



### Step 8: Gateway 返回给 Agent 结果

`Agent <-- Gateway <-- App`