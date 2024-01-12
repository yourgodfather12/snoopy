def print_failed_tests(failed_tests):
    if failed_tests:
        print("\nFailed Tests:")
        for test in failed_tests:
            print(f"- {test}")
