package jwt.hello.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import jwt.hello.vo.JwtUser;

@Mapper
public interface JwtMapper {
	
	public List<JwtUser> selectUsers();
	
	public JwtUser selectUser(@Param("username") String username);
	
	public String selectRoles(@Param("username") String username);

//	public List<MpRuleDto> selectMpRule(MpRuleDto params);
//
//	public void insertMpRuleMaster(MpRuleDto params);
//
//	public int insertMpRuleDetail(MpRuleDto params);
//
//	public int insertFareRuleDetail(AnalysisRequestFareRuleDto params);
	
}