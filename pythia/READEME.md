#Pythia PRF experiment 
##Setup
1. Download safeid from https://github.com/ace0/safeid commit d4fe9b8531a7a248068299e7420e8d9381042c1e
2. Replace safeid.py with the safeid.py found with this document
3. Make sure that the ersatz python library is in the path before running safeid.

##Testing
The following will test to see if everything is working properly. Note the output of "new" and replace where approriate. 
To create a new entry: safeid new 'krix' 'pw' -s http://127.0.0.1:8000
Check true password: safeid check 'krix' 'pw' '["IJThhxs9YgfAEStCO0RcF39nZ6kgWYxW", "6cie6Asi5ah-sH1ukaYb-UTzJvX0xSx7", "Es-UFO5UfJK9gZCQ_rKTxq6TL68rRRKwDj9jF-hC_mMTIc5FUaGVfLy7ljO1kFWR_s-0j_uaJjsyEFa_V3fUjwEPpSJTkangXfViCoAo_I9V7LV0WCZCZtBGmJx77UoKF_Qb3Jc36YbpE5we4Cnr8kW8wykfBvkFd9KiHUv8Dk0PfYVY6zhiCXdricwVhUCOkPm89Ed7yHlObROsnJwtmAkbX_9gn-aAqXqfxUGLFXWyqPxm4WCeRb7kwgkbXohWDdNMhJYT0xo9qefBedSWpckraVsUb1OiUAE7TJC70jED5XZ3oNgLNv0U9byUEwq0aI6dafo5tRs8nNIbLcFdWw==", "AhFVM7q6MG8MCmZDqv2VjWbebKGKvFDu2pVhMXl7WEsr"]' -s http://127.0.0.1:8000
Check ersatz password: safeid check 'krix' 'ersatz' '["E7CfNG_CfpEWPyCpRGSjQFqVt1ZsXHIc", "9QrT5sZx", "CqYhF_RyRdWreJhzeRjy0UZIubehRPK0Pj0V3qllfL0Rg_u5p4QQS12CUIXPPPRlS66rXKRpRYuNhtgL8j1KPxzykJCmYxp5iG9dRWTACj3znU_634kvkjqrmOwxgUuyDpgvbWRYTXxRFe0H5nAE7vftl9dCqomangZUqzGB2SkPAUrKEM5gY1UdeMZ9fwyqNyr1SuRbN3tWCkr0NmEr_QJVEKnvZzRd3EdP0G6qKlQtZmNJ9H8_C5rDCvSQDIfoBrvft1eSiFcPZNiJ6J7XdjrA8WJCxgXajnRasSV1SrUTa6o_e-Lo0FJNhVkUfXJLRtDrLL8HtpdBU9F3vbvPTg==", "AiDo-sA8KL4PGWZLveWG7VrzWaW2HYnYp33qWZWfAm4q"]' -s http://127.0.0.1:8000
Update: safeid update 'krix'  'pw' '["E7CfNG_CfpEWPyCpRGSjQFqVt1ZsXHIc", "9QrT5sZx", "CqYhF_RyRdWreJhzeRjy0UZIubehRPK0Pj0V3qllfL0Rg_u5p4QQS12CUIXPPPRlS66rXKRpRYuNhtgL8j1KPxzykJCmYxp5iG9dRWTACj3znU_634kvkjqrmOwxgUuyDpgvbWRYTXxRFe0H5nAE7vftl9dCqomangZUqzGB2SkPAUrKEM5gY1UdeMZ9fwyqNyr1SuRbN3tWCkr0NmEr_QJVEKnvZzRd3EdP0G6qKlQtZmNJ9H8_C5rDCvSQDIfoBrvft1eSiFcPZNiJ6J7XdjrA8WJCxgXajnRasSV1SrUTa6o_e-Lo0FJNhVkUfXJLRtDrLL8HtpdBU9F3vbvPTg==", "AiDo-sA8KL4PGWZLveWG7VrzWaW2HYnYp33qWZWfAm4q"]' -s http://127.0.0.1:800

##Measuring latency
In the commands above, append "_latency" to "new" or "check" to run for 1000 iterations and output a .csv file