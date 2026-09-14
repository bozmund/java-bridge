#!/bin/sh
# End-to-end demo: compile the sample classes, then reverse one method with
# reagent + java-bridge using the configured LLM (examples/demo/reagent.yaml).
set -e
cd "$(dirname "$0")"
javac -d classes src/com/example/demo/*.java
if [ ! -f java-bridge.yaml ]; then
    java-bridge init classes
fi
ADDR=$(java-bridge search rankOf | awk '{print $1}')
echo "reversing com.example.demo.ScoreKeeper::rankOf at $ADDR"
reagent-java --config reagent.yaml reverse --address "$ADDR"
