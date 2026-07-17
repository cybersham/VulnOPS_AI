from dotenv import load_dotenv
load_dotenv(".env.local")

import ollama
from database import sessionLocal
from mcp_server import get_open_findings, get_kev_findings, ask_vulnerability_question


# Step 1: Describe our tools in the JSON schema format Ollama expects
# (This mirrors what MCP does automatically via docstrings + @mcp.tool() —
# here we're writing that "contract" by hand instead.)
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_open_findings",
            "description": "Returns all vulnerability findings that are currently open (unpatched), across all tracked repositories.",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_kev_findings",
            "description": "Returns open findings whose CVE is on CISA's Known Exploited Vulnerabilities (KEV) list — actively exploited in the wild, needing urgent remediation.",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "ask_vulnerability_question",
            "description": "Answers fuzzy, natural-language questions about vulnerabilities using semantic search over CVE descriptions. Use for open-ended questions that don't map to an exact filter.",
            "parameters": {
                "type": "object",
                "properties": {
                    "question": {"type": "string", "description": "The user's natural-language question"}
                },
                "required": ["question"]
            }
        }
    }
]

# Step 2: Map tool names (strings) to the actual Python functions that do the work
AVAILABLE_FUNCTIONS = {
    "get_open_findings": get_open_findings,
    "get_kev_findings": get_kev_findings,
    "ask_vulnerability_question": ask_vulnerability_question
}


def chat(user_question: str) -> str:
    messages = [{"role": "user", "content": user_question}]

    # First call: give Ollama the question + tool descriptions
    response = ollama.chat(
        model="llama3.1",
        messages=messages,
        tools=TOOLS
    )

    # Check if the model wants to call a tool
    if response["message"].get("tool_calls"):
        messages.append(response["message"])  # record the model's tool-call request

        for tool_call in response["message"]["tool_calls"]:
            function_name = tool_call["function"]["name"]
            function_args = tool_call["function"]["arguments"]

            print(f"[Ollama wants to call: {function_name}({function_args})]")

            function_to_call = AVAILABLE_FUNCTIONS[function_name]
            result = function_to_call(**function_args)

            # Feed the real result back to the model as a "tool" message
            messages.append({
                "role": "tool",
                "content": str(result)
            })

        # Second call: now let the model write a final answer using the tool's result
        final_response = ollama.chat(model="llama3.1", messages=messages)
        return final_response["message"]["content"]

    # No tool needed — model answered directly
    return response["message"]["content"]


if __name__ == "__main__":
    print("VulnOps AI — Ollama Chat (type 'exit' to quit)\n")
    while True:
        question = input("You: ")
        if question.lower() == "exit":
            break
        answer = chat(question)
        print(f"\nAssistant: {answer}\n")