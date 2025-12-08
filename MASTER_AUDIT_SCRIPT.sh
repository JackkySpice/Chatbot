#!/bin/bash
# Master Audit Script for BestChange.com
# Combines all audit tools and generates comprehensive report

echo "=========================================="
echo "BestChange.com Master Security Audit"
echo "=========================================="
echo ""
echo "Starting comprehensive audit..."
echo ""

# Run all audit scripts
echo "[1/5] Running initial comprehensive audit..."
python3 /workspace/bestchange_audit.py > /tmp/audit1.log 2>&1

echo "[2/5] Running advanced audit with encoding bypasses..."
python3 /workspace/bestchange_audit_advanced.py > /tmp/audit2.log 2>&1

echo "[3/5] Running specialized tests..."
python3 /workspace/bestchange_specialized_tests.py > /tmp/audit3.log 2>&1

echo "[4/5] Running deep analysis..."
python3 /workspace/bestchange_deep_analysis.py > /tmp/audit4.log 2>&1

echo "[5/5] Running business logic tests..."
python3 /workspace/bestchange_business_logic.py > /tmp/audit5.log 2>&1

echo ""
echo "=========================================="
echo "Generating final comprehensive report..."
echo "=========================================="
echo ""

python3 /workspace/bestchange_final_report.py

echo ""
echo "=========================================="
echo "Audit Complete!"
echo "=========================================="
echo ""
echo "All audit logs saved to /tmp/audit*.log"
echo "Summary report: /workspace/AUDIT_SUMMARY.md"
echo ""
