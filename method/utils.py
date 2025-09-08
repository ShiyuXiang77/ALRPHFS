import re
import json
import logging
from typing import Dict, Any, List, Tuple, Optional, Union
from openai import OpenAI
import time
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
class LLMClient:
    """Client for interacting with the LLM API"""

    def __init__(self, api_key: str, base_url: str, model: str):
        self.client = OpenAI(
            api_key=api_key,
            base_url=base_url,

        )
        self.model = model
# ================================
# Utility Functions
# ================================
    def parse_json_response(self,response: str) -> Dict[str, Any]:
        """
        Parse JSON from an LLM response.
        Handles both direct JSON responses and JSON within code blocks.
        """
        if not response:
            logger.warning("Empty response received")
            return {}
        try:
            # First try direct parsing
            return json.loads(response)
        except json.JSONDecodeError:
            # Try to extract JSON from code blocks
            match = re.search(r'```(?:json)?\s(.+?)\s```', response, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(1))
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse JSON from code block: {e}")

            # Try to extract anything that looks like JSON
            match = re.search(r'(\{.+\})', response, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(1))
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse JSON from content: {e}")

        logger.warning(f"Could not extract valid JSON from: {response}")
        return {}

    def response(self, messages, tools=None,temperature=0.9):
        # if not tools: tools = None
        if isinstance(messages, str):
            messages = [
                {"role": "user", "content": messages},
            ]

        for _ in range(5):
            try:
                if tools is None:
                    response = self.client.chat.completions.create(
                        model=self.model,
                        messages=messages,
                        stream=False,
                        response_format={"type": "json_object"},
                        temperature=temperature,
                    )
                    length = response.usage.total_tokens
                    return response.choices[0].message.content,length
                else:
                    completion = self.client.chat.completions.create(
                        model=self.model,
                        tools=tools,
                        messages=messages,
                    )
                    print(f'completion: {completion}')
                    if completion is None or completion.choices is None:
                        continue
                    return completion
            except Exception as e:
                print(e)
                time.sleep(3)

   #Need to call tool
    def generate_response(self, messages, tools):
        completion = self.response(messages, tools)
        # print(f'messages: {messages}\ncompletion: {completion}')

        if completion is None: return None
        finish_reason = completion.choices[0].finish_reason
        ## tool call part
        # print(f'completion: {completion}')
        if completion.choices[0].message.tool_calls is not None:
            tool_call = completion.choices[0].message.tool_calls[0]
            tool_call_id = tool_call.id
            tool_name = tool_call.function.name
            if tool_call.function.arguments:
                arguments = json.loads(tool_call.function.arguments)
            else:
                arguments = {}
            return {'type': 'tool', 'tool_call_id': tool_call_id, 'tool_name': tool_name,
                    'arguments': arguments, 'finish_reason': finish_reason}
        else:
            content = completion.choices[0].message.content
            return {'type': 'content', 'content': content, 'finish_reason': finish_reason}