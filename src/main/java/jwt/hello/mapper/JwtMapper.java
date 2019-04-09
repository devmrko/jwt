package jwt.hello.mapper;

import java.util.List;
import java.util.Map;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import jwt.hello.vo.CarUseHistParam;
import jwt.hello.vo.JwtUser;

@Mapper
public interface JwtMapper {
	
	public List<JwtUser> selectUsers();
	
	public JwtUser selectUser(@Param("username") String username);
	
	public String selectRoles(@Param("username") String username);
	
	public int selectIsUrlEnabled(@Param("request_url") String requestUrl, @Param("request_method") String requestMethod, @Param("rolename") String rolename);
	
	public void insertRefreshToken(@Param("token") String token, @Param("username") String username);
	
	public int updateRefreshTokenAsUsed(@Param("token") String token, @Param("username") String username);
	
	public List<Map<String, String>> selectMenu();
	
	public List<Map<String, String>> selectMemos();
	
	public Map<String, String> selectMemo(@Param("id") String id);
	
	public void insertMemo(@Param("title") String title, @Param("contents") String contents);
	
	public void updateMemo(@Param("id") String id, @Param("title") String title, @Param("contents") String contents);
	
	public void deleteMemo(@Param("id") String id);	
	
	public List<Map<String, String>> selectComcode(int mastrcd);
	
	public List<Map<String, String>> selectCarUseHist(CarUseHistParam carUseHistParam);
	
	public int insertCarUseHist(CarUseHistParam carUseHistParam);
	
//	public List<MpRuleDto> selectMpRule(MpRuleDto params);
//
//	public void insertMpRuleMaster(MpRuleDto params);
//
//	public int insertMpRuleDetail(MpRuleDto params);
//
//	public int insertFareRuleDetail(AnalysisRequestFareRuleDto params);
	
}