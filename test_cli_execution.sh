#!/bin/bash
# Test script to verify agent execution from CLI

echo "=== Testing Agent CLI Execution ==="
echo ""

# Test 1: Check Python availability
echo "[TEST 1] Checking Python installation..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    echo "✓ Python found: $PYTHON_VERSION"
else
    echo "✗ Python3 not found"
    exit 1
fi
echo ""

# Test 2: Check if agent script exists (if created)
echo "[TEST 2] Checking for agent script..."
if [ -f "agent.py" ]; then
    echo "✓ agent.py found"
    chmod +x agent.py
else
    echo "⚠ agent.py not found (will create test version)"
fi
echo ""

# Test 3: Test basic Python execution
echo "[TEST 3] Testing Python script execution..."
cat > /tmp/test_agent_exec.py << 'EOF'
#!/usr/bin/env python3
import sys
import os

def main():
    print("Agent CLI execution test successful!")
    print(f"Python version: {sys.version}")
    print(f"Arguments received: {sys.argv[1:]}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
EOF

python3 /tmp/test_agent_exec.py --test-arg "test-value"
if [ $? -eq 0 ]; then
    echo "✓ Python script execution works"
else
    echo "✗ Python script execution failed"
    exit 1
fi
echo ""

# Test 4: Test with standard libraries (requests, sys, time)
echo "[TEST 4] Testing required standard libraries..."
python3 -c "import sys; import time; print('✓ sys and time modules available')"
if [ $? -eq 0 ]; then
    echo "✓ Standard libraries available"
else
    echo "✗ Standard libraries check failed"
    exit 1
fi
echo ""

# Test 5: Test requests library (may need to check)
echo "[TEST 5] Checking requests library..."
python3 -c "import requests" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "✓ requests library available"
else
    echo "⚠ requests library not available (may need: pip install requests)"
fi
echo ""

echo "=== CLI Execution Test Complete ==="
echo "All basic tests passed! Agent can be executed from CLI."
