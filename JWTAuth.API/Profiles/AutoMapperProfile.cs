using AutoMapper;
using JWTAuthSecuredAPI.Entities;
using JWTAuthSecuredAPI.Models;

namespace JWTAuthSecuredAPI.Profiles
{
    public class AutoMapperProfile : Profile
    {
        public AutoMapperProfile()
        {
            CreateMap<RegisterRequestModel, UserEntity>()
                .ForMember(destination => destination.UserName, opt => opt.MapFrom(x => x.Username));
        }
    }
}
