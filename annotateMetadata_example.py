####### This workflow only annotates the STIXnet text excerpts #####


####################################################################

import time # so i dont kill my computer i need to set a sleep for data processing

# Agno Agent stuff
from agno.agent import Agent, RunOutput
from agno.utils.pprint import pprint_run_response
from agno.models.ollama import Ollama
from agno.run.agent import RunEvent

# Agno Workflow stuff
from agno.workflow.types import WorkflowExecutionInput
from agno.workflow.workflow import Workflow, WorkflowRunEvent
from agno.workflow.step import Step
from agno.workflow.condition import Condition
from agno.workflow.types import StepInput, StepOutput

# Auxiliary stuff
import json
import os
from agno.db.sqlite import SqliteDb

#user_defined_model = "gemma3:12b"
#user_defined_model = "mistral:7b"
user_defined_model = "phi4:14b"

# import metadata agents
from metadataAgents.metaagents import tagger, reviewer, topicsDict
tagger.model=Ollama(id=user_defined_model, options={"num_ctx":8192, "temperature":0.1}, keep_alive=0)
reviewer.model=Ollama(id=user_defined_model, options={"num_ctx":8192, "temperature":0.02}, keep_alive=0)

# global hack
current_doc_number = 0

# uncomment this to change models to your own version
#tagger.model=Ollama(id="phi4:14b", options={"num_ctx":10000, "temperature":0.1})

reportFile = "./datasets/inputs/reports/sample_report.txt"

def getReport(report):
    with open(report, "r", encoding='utf-8') as file:
        file_content = file.read()
        
    return file_content
        
    
       
        

# conditional step that determines if review is needed
def needs_reviewing(step_input: StepInput) -> bool:
    
    "Determine if the metadata tagging is valid or requires fact-checking"
    valid_topics = topicsDict.keys()
    
    annotated_topics = step_input.previous_step_content
    
    # Convert to dict if it's a Pydantic model
    if hasattr(annotated_topics, 'model_dump'):
        output_dict = annotated_topics.model_dump()
    elif isinstance(annotated_topics, str):
        output_dict = json.loads(annotated_topics)
    else:
        output_dict = annotated_topics
    
    print("####### annotated_dict: ", output_dict)
    
    topics = output_dict["documents"][0]["pages"][0]["topics"]
    for topic in topics:
        if topic not in valid_topics:
            return True

    return False
    
# conditional step that determines if review is needed
def doesnt_needs_reviewing(step_input: StepInput) -> bool:
    
    "Determine if the metadata tagging is valid or requires fact-checking"
    valid_topics = topicsDict.keys()
    
    annotated_topics = step_input.get_step_content("Annotate Metadata Step")
    
    print("############# type:", type(annotated_topics))
    
    # Convert to dict if it's a Pydantic model
    if hasattr(annotated_topics, 'model_dump'):
        output_dict = annotated_topics.model_dump()
    elif isinstance(annotated_topics, str):
        output_dict = json.loads(output_dict)
    else:
        output_dict = annotated_topics
    
    topics = output_dict["documents"][0]["pages"][0]["topics"]
    
    for topic in topics:
    
        if topic in valid_topics:
            return True

    return False

'''    
def write_to_file(step_input: StepInput) -> StepOutput:
    "Write the metadata output to a file"
    output = step_input.previous_step_content
    
    global current_doc_number # hacked solution
    
    # Write to a file
    with open(f"{current_doc_number}_metadata_output.json", "w") as f:
        f.write(str(output))
        
    return StepOutput(content=f"Output written to metadata_output.json")
'''

def write_to_file(step_input: StepInput) -> StepOutput:
    "Write the metadata output to a JSON file"
    output = step_input.previous_step_content
    
    global current_doc_number
    
    # Convert to dict if it's a Pydantic model
    if hasattr(output, 'model_dump'):
        output_dict = output.model_dump()
    elif isinstance(output, str):
        output_dict = json.loads(output)
    else:
        output_dict = output
    
    # Write to JSON file
    with open(f"./datasets/outputs/STIXnet/annotations/sample/test1_{current_doc_number}_metadata_output.json", "w", encoding='utf-8') as f:
        json.dump(output_dict, f, indent=2)
        
    return StepOutput(content=f"Output written to {current_doc_number}_metadata_output.json")


def valid_write(step_input: StepInput) -> StepOutput:
    annotate_output = step_input.get_step_content("Annotate Metadata Step")
    return StepOutput(content=annotate_output)

#### Define workflow steps
annotate_step = Step(
    name = "Annotate Metadata Step",
    agent=tagger,
    max_retries=2 
)

review_step = Step(
    name="Review Step",
    description="Verify metatadata topics are valid",
    agent=reviewer,
    max_retries=2
)

write_step = Step(
    name="Write Output Step",
    executor=write_to_file,
    max_retries=2
)

valid_write_step = Step(
    name="Valid Write Step",
    executor=valid_write
)

metadata_annotation_workflow = Workflow (
    name="Annotation Metadata Workflow",
    description="Annotation of cyber threat report data based on a provided set of metadata topics",
    steps = [annotate_step, 
            Condition(
                name="fact_check_condition",
                description="Check if fact-checking is needed",
                evaluator=needs_reviewing,
                steps=[review_step, write_step]
        ),
        Condition(
                name="fact_check_condition",
                description="Check if fact-checking is not needed",
                evaluator=doesnt_needs_reviewing,
                steps=[valid_write_step, write_step]
        ),
        ],
    
)


if __name__ == "__main__":      
    excerpt = getReport(reportFile)
    
    print("Excerpt: ", excerpt)
    current_doc_number = 0

    # Create and use workflow

    metadata_annotation_workflow.print_response(
        input=fr"The document text to process is: '{excerpt}', For the JSON output: The document ID is: {current_doc_number}, the page number is: {0}. The title is: 'sample_report'. Include the full document text in the JSON output.",
        markdown=True,
        stream=True, # enable streaming
        stream_events=True # stream workflow events
    )
    

