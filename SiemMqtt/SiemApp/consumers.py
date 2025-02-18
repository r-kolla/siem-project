import json
from channels.generic.websocket import AsyncWebsocketConsumer

class LogConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.channel_layer.group_add("logs", self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard("logs", self.channel_name)

    async def receive(self, text_data):
        pass  # No need to handle incoming messages from client

    async def send_log(self, event):
        log_message = event["message"]
        await self.send(text_data=json.dumps(log_message))
