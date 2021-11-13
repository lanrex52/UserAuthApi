using AutoMapper;
using UserAuthApi.Entities;
using UserAuthApi.Models.Accounts;

namespace UserAuthApi.Helpers
{
    public class AutomapperProfile:Profile
    {
        // mapp model objects and entity objects
        public AutomapperProfile()
        {
            CreateMap<Account, AccountResponse>();
            CreateMap<Account, LoginResponse>();
            CreateMap<RegistrationRequest, Account>();
            CreateMap<CreateRequest, Account>();
            CreateMap<UpdateRequest, Account>()
                .ForAllMembers(x => x.Condition(
                    (src, dest, prop) =>
                    {
                        //ignore null and empty string properties
                        if (prop == null) return false;
                        if (prop.GetType() == typeof(string) && string.IsNullOrEmpty((string)prop))
                            return false;
                        //ignore null role
                        if (x.DestinationMember.Name == "Role" && src.Role == null) return false;


                        return true;


                    }
                    ));

        }
    }
}
