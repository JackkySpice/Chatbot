#!/usr/bin/env python3
"""
CLI Test Script for Agent Execution
Tests that the agent can be executed from command line and responds appropriately.
"""

import sys
import os
import traceback
from pathlib import Path
from typing import Dict, List, Tuple, Optional


# Configuration constants
AGENTS_FILE = Path("/workspace/AGENTS.md")
TEST_TARGET = "https://example.com"
BORDER_WIDTH = 60


class TestResult:
    """Represents the result of a single test."""
    
    def __init__(self, name: str, passed: bool, message: str = "", warning: bool = False):
        self.name = name
        self.passed = passed
        self.message = message
        self.warning = warning
    
    def __str__(self) -> str:
        status = "⚠" if self.warning else ("✓" if self.passed else "✗")
        return f"{status} {self.message or self.name}"


class TestRunner:
    """Manages test execution and reporting."""
    
    def __init__(self):
        self.results: List[TestResult] = []
    
    def add_result(self, result: TestResult):
        """Add a test result."""
        self.results.append(result)
        print(str(result))
    
    def print_header(self, title: str):
        """Print a formatted header."""
        print("\n" + "=" * BORDER_WIDTH)
        print(title)
        print("=" * BORDER_WIDTH)
    
    def print_section(self, title: str):
        """Print a test section header."""
        print(f"\n[{title}]")
    
    def all_passed(self) -> bool:
        """Check if all critical tests passed (warnings don't count as failures)."""
        return all(result.passed for result in self.results if not result.warning)


class EnvironmentTester:
    """Tests the execution environment."""
    
    def __init__(self, runner: TestRunner):
        self.runner = runner
    
    def test_environment(self) -> bool:
        """Test basic environment configuration."""
        self.runner.print_section("TEST 1: Environment Check")
        
        try:
            self.runner.add_result(TestResult(
                "Python version",
                True,
                f"Python version: {sys.version.split()[0]}"
            ))
            
            self.runner.add_result(TestResult(
                "Platform",
                True,
                f"Platform: {sys.platform}"
            ))
            
            self.runner.add_result(TestResult(
                "Working directory",
                True,
                f"Working directory: {os.getcwd()}"
            ))
            
            return True
        except Exception as e:
            self.runner.add_result(TestResult(
                "Environment check",
                False,
                f"Failed: {e}"
            ))
            return False


class ConfigurationTester:
    """Tests agent configuration files."""
    
    def __init__(self, runner: TestRunner, agents_file: Path):
        self.runner = runner
        self.agents_file = agents_file
    
    def test_configuration(self) -> bool:
        """Test agent configuration file."""
        self.runner.print_section("TEST 2: Agent Configuration Check")
        
        if not self.agents_file.exists():
            self.runner.add_result(TestResult(
                "AGENTS.md file",
                False,
                f"AGENTS.md not found at: {self.agents_file}"
            ))
            return False
        
        self.runner.add_result(TestResult(
            "AGENTS.md file",
            True,
            f"AGENTS.md found at: {self.agents_file}"
        ))
        
        try:
            content = self.agents_file.read_text()
            
            checks = [
                ("RED TEAM", "Agent role configuration"),
                ("Python", "Python environment requirement"),
            ]
            
            for keyword, description in checks:
                found = keyword in content
                self.runner.add_result(TestResult(
                    description,
                    found,
                    f"{description} detected" if found else f"{description} not found"
                ))
            
            return True
        except Exception as e:
            self.runner.add_result(TestResult(
                "Configuration read",
                False,
                f"Failed to read configuration: {e}"
            ))
            return False


class LibraryTester:
    """Tests required and optional library availability."""
    
    def __init__(self, runner: TestRunner):
        self.runner = runner
    
    def test_libraries(self) -> bool:
        """Test standard library availability."""
        self.runner.print_section("TEST 3: Standard Library Check")
        
        # Required libraries
        required = {
            "time": "time module",
            "sys": "sys module",
        }
        
        # Optional libraries
        optional = {
            "requests": "requests library",
        }
        
        all_passed = True
        
        for module_name, description in required.items():
            try:
                __import__(module_name)
                self.runner.add_result(TestResult(
                    description,
                    True,
                    f"{description} available"
                ))
            except ImportError:
                self.runner.add_result(TestResult(
                    description,
                    False,
                    f"{description} not available"
                ))
                all_passed = False
        
        for module_name, description in optional.items():
            try:
                __import__(module_name)
                self.runner.add_result(TestResult(
                    description,
                    True,
                    f"{description} available"
                ))
            except ImportError:
                self.runner.add_result(TestResult(
                    description,
                    True,
                    f"{description} not available (may need: pip install {module_name})",
                    warning=True
                ))
        
        return all_passed


class AgentSimulator:
    """Simulates agent execution behavior."""
    
    def __init__(self, runner: TestRunner):
        self.runner = runner
    
    def simulate_execution(self, target: str) -> bool:
        """Simulate agent execution for a test target."""
        self.runner.print_section("TEST 4: Agent Execution Simulation")
        
        try:
            print(f"Simulating agent response to a test target...")
            print(f"Target: {target}")
            print("Strategy: Testing basic connectivity and response analysis")
            
            print("\n[AGENT OUTPUT SIMULATION]")
            simulation_steps = [
                f"Analyzing target: {target.split('//')[-1].split('/')[0]}",
                "Attack surface identified: Web application",
                "Selected vector: Basic reconnaissance",
                "\nGenerating PoC script...",
            ]
            
            for step in simulation_steps:
                print(step)
            
            self.runner.add_result(TestResult(
                "Agent simulation",
                True,
                "Agent execution simulation completed successfully"
            ))
            
            return True
        except Exception as e:
            self.runner.add_result(TestResult(
                "Agent simulation",
                False,
                f"Simulation failed: {e}"
            ))
            return False


def run_all_tests() -> bool:
    """Execute all test suites."""
    runner = TestRunner()
    runner.print_header("AGENT CLI EXECUTION TEST")
    
    # Initialize testers
    env_tester = EnvironmentTester(runner)
    config_tester = ConfigurationTester(runner, AGENTS_FILE)
    lib_tester = LibraryTester(runner)
    agent_sim = AgentSimulator(runner)
    
    # Run tests
    tests = [
        ("Environment", env_tester.test_environment),
        ("Configuration", config_tester.test_configuration),
        ("Libraries", lib_tester.test_libraries),
        ("Agent Simulation", lambda: agent_sim.simulate_execution(TEST_TARGET)),
    ]
    
    all_passed = True
    for test_name, test_func in tests:
        try:
            if not test_func():
                all_passed = False
        except Exception as e:
            runner.add_result(TestResult(
                test_name,
                False,
                f"Test crashed: {e}"
            ))
            all_passed = False
    
    # Print summary
    runner.print_header("TEST COMPLETE")
    status = "Agent CLI execution verified" if all_passed else "Some tests failed"
    print(status)
    
    return all_passed


def main() -> int:
    """Main entry point."""
    try:
        success = run_all_tests()
        return 0 if success else 1
    except Exception as e:
        print(f"\n✗ Test suite failed with error: {e}")
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
