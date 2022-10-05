Demo functionality.

Make sure the Demo account's API key is saved to the system this is running on by saving the key to the environment value of "NETWORKSAGE_DEMO_API_KEY"

To run an end-to-end demo (with timing and useful info for a person to see), do:
python3 demo.py --action e2e --file PCAPs/blahblah.pcap

The above will produce a lightly-formatted output.md file (use --outputfile blahblah.md to specify output filename) that can be viewed in a Markdown viewer like MacDown.

To get the Categorization or Summary for a sample whose private ID already exists (and is owned by the Demo user), type:

python3 demo.py --action {categorization, summary} --sampleid <ID> --outputfile {categorization.json, summary.json} 

This will produce the categorization or summary in the supplied name. It should be viewed in a JSON-aware viewer such as IntelliJ IDEA.
