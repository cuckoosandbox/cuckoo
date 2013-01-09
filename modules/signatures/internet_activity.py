# Found this useful when the Network Analysis section wasn't 
# providing the URL and GET information I was looking for,
# but the Processes section did.
# Looking for more helpful API calls to be added from the community


from lib.cuckoo.common.abstracts import Signature

class InternetOpen(Signature):
    name = "InternetOpenA & InternetOpenUrlA"
    description = "Internet Activity (Look at Processes)"
    severity = 3
    categories = ["generic"]
    authors = ["Marcus"]
    minimum = "0.4"

    def run(self):
        for process in self.results["behavior"]["processes"]:
            for call in process["calls"]:
                if call["api"] == "InternetOpenA":
                    return True
                if call["api"] == "InternetOpenUrlA":
                    return True
        return False
