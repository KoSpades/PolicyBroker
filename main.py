from fastapi import FastAPI
from intentObject import Intent
import casbin


# Creating the Casbin enforcer based on model.conf and policy.csv
e = casbin.Enforcer("model.conf", "policy.csv")


# Now we write a function to check if the intent matches a policy
# using Casbin
def check_intent(intent: Intent):
    return e.enforce(intent.subject, intent.object, intent.action)


# Start running the application
app = FastAPI()


@app.get("/")
async def welcome():
    return {"message": "Welcome to Policy Broker"}


@app.post("/check")
async def receive_intent(intent: Intent):
    result = check_intent(intent)
    return {"intent is valid?": result}

