"""Minimal Gradio application for Nerva fingerprinter integration testing."""

import gradio as gr


def greet(name):
    return f"Hello, {name}!"


demo = gr.Interface(fn=greet, inputs="text", outputs="text", title="Test App")
demo.launch(server_name="0.0.0.0", server_port=7860)
