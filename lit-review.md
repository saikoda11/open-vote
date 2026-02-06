# Blockchain-Based E-Voting Mechanisms: A Survey and a Proposal 

https://doi.org/10.3390/network4040021

Blockchain systems:
Permissionless, Permissioned, Hybrid (open access to authority that gives access), Consortium

Voting Strategies: 
- Borda Count 
    each voter ranks candidates, higher score given for being higher, total count wins, problem - people vote for people just so that disliked majority winner does not win

- Condorcet Method 

    each voter decides which candidate wins in 1v1 setups against each other, 1 point per win in 1v1, highest scorer from all rankings wins, problem - circle

Both strategies are kept in blockchain by smart markers for branching and merging.
The purpose of having both is to aleviate the weaknesses of both.

# Blockchain-Based Electronic Voting System: Significance and Requirements

https://doi.org/10.1155/2024/5591147

> This paper seems to provide a good design prototype for off-chain and on-chain operations

Voters get token from authority.

Then they vote and provide ZKSMP to prove vote validity.

Then it is added to the blockchain.

The tally of their vote can be verified by public address.

Proof of Authority validators mine and add the vote to chain.

# Blockchain for Electronic Voting System—Review and Open Research Challenges

https://pmc.ncbi.nlm.nih.gov/articles/PMC8434614/pdf/sensors-21-05874.pdf

The paper reviews current solutions on this topic.

Can be used to select relevant solution to our project.
