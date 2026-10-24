"""Train a three-seed candidate ensemble using training-only encoding."""
def main():
    from training import run
    run(ensemble=True)

if __name__ == "__main__":
    main()
