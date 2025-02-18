
class Database:

    def __init__(self):
        self.USERS = {"test":set(),"string":set()}
        self.APPLICATIONS = {}
        self.DEPENDENCIES = {}



#     def add_application(self,app_id : str,app_name : str,app_description : str):
#         self.USERS["applications"].add(app_id)
#         self.APPLICATIONS[app_id] = {"name": app_name, "description": app_description,"vulnerabilities":0,"dependencies":{},"status": "processing"}
#
#     def get_application(self,app_id : str):
#         return self.APPLICATIONS[app_id]
#
#     def update_application(self,app_id : str,app_name : str,app_description : str):
#         # self.APPLICATIONS[app_id]["name"] = app_name
#         # self.APPLICATIONS[app_id]["description"] = app_description
#
# database = Database()
# database.add_application("1","app1","app1 description")
#
# print(database.USERS)

database = Database()
