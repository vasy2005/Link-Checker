Malware Link Checker

Uses various databases and indicators of compromise to suggest whether the URL might be harmful:
1. VirusTotal API
2. ThreatFox API
3. Google Safe Browsing API
4. WHOIS Lookup
5. DNS TTL
6. Lexical indicators: number of characters/digits, Shannon Entropy, Homoglyph detection, Levenshtein distance

The URL is first normalized and then, based on the indicators above, a feature array is calculated and the outputs of the APIs
mentioned above get saved in a .json.
The indicators have been used to train a Random Forest Classifier ML that could output a probability of the link being harmful.
(Note: due to the APIs having a limit on requests the training data used is not sufficient and needs to be improved)

There is a class built for each of the 3 APIs:
1. CheckGoogleSB
2. CheckThreatFox
3. CheckVirusTotal
To use them the api keys need to be set up as environment variables.
