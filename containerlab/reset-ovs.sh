#!/bin/bash
# ============================================
# Reset OVS Configuration
# ============================================

echo "Resetting OVS switches..."

for BR in spine1 spine2 leaf1 leaf2 leaf3
do
  ovs-vsctl --if-exists del-br $BR
done

echo "OVS bridges removed."
