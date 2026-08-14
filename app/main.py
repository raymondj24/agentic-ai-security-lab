from dotenv import load_dotenv

from app.agent import ask_agent


load_dotenv()


def main():
    print("SentinelAI v0.1")
    print("Type 'exit' to quit.\n")

    while True:
        user_input = input("You: ")

        if user_input.lower() == "exit":
            print("Goodbye.")
            break

        response = ask_agent(user_input)

        print(f"\nSentinelAI: {response}\n")


if __name__ == "__main__":
    main()