
from langflow.custom import Component
from langflow.io import Input, Output
from langflow.schema import Data
from langchain.llms import OpenAI

class LLMAnalyzer(Component):
    display_name = "LLM Analyzer"
    description = "Analyzes data with an LLM."
    icon = "robot"

    inputs = [
        Input(name="data_to_analyze", display_name="Data to Analyze", required=True),
        Input(name="api_key", display_name="OpenAI API Key", required=True, password=True)
    ]

    outputs = [
        Output(display_name="Analysis Result", name="analysis_result", method="analyze_data")
    ]

    def analyze_data(self) -> Data:
        llm = OpenAI(api_key=self.api_key)
        result = llm.predict(self.data_to_analyze)
        return Data(data={"analysis_result": result})
