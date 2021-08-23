from fastapi import Depends, FastAPI
from intentObject import Intent


app = FastAPI()


# Now we write a function to check if the intent matches a policy
# once this is done, we change this to using Casbin instead


@app.get("/")
async def welcome():
    return {"message": "Welcome to Policy Broker"}


@app.post("/check")
async def receive_intent(intent: Intent):
    return {"intended action": intent.action}

