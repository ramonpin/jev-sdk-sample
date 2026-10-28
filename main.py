from typesafe_sdk import Choice, TypeSafeClient

with TypeSafeClient() as client:
    response = client.system_one(
        state={
            "command": "sed -ie 's/pepe/juan/g' /home/ramon/file",
            "cwd": "/dev/shm",
        },
        questions={
            "security": Choice(
                instructions="How dangerous is this command?",
                criteria={"reads": None, "modifies": None, "deletes": None},
            ),
            "external": Choice(
                instructions="Access outside cwd?", criteria={"yes": None, "no": None}
            ),
        },
    )

print(response.choices["security"].choice)
print(response.choices["external"].choice)
