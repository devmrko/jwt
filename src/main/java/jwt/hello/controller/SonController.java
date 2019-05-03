package jwt.hello.controller;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.google.gson.Gson;

import jwt.hello.mapper.JwtMapper;
import jwt.hello.service.JwtProvider;
import jwt.hello.vo.CarUseHistParam;

@RestController
@RequestMapping(value = "/rest")
public class SonController {

	@Autowired
	JwtMapper jwtMapper;
	
	@Autowired
	JwtProvider jwtProvider;

	@RequestMapping(method = RequestMethod.GET, path = "/menu")
	public String selectMenu() {
		Gson gson = new Gson();
		String result = gson.toJson(jwtMapper.selectMenu(), List.class);
		return result;
	}

	@RequestMapping(method = RequestMethod.GET, path = "/memo")
	public String selectMemos() {
		Gson gson = new Gson();
		String result = gson.toJson(jwtMapper.selectMemos(), List.class);
		return result;
	}

	@RequestMapping(method = RequestMethod.GET, path = "/memo/{id}")
	public String selectMemo(@PathVariable String id) {
		Gson gson = new Gson();
		String result = gson.toJson(jwtMapper.selectMemo(id), List.class);
		return result;
	}

	@RequestMapping(method = RequestMethod.PUT, path = "/menu")
	public void insertMenu(@RequestParam("title") String title, @RequestParam("contents") String contents) {
		jwtMapper.insertMemo(title, contents);
	}

	@RequestMapping(method = RequestMethod.POST, path = "/menu/{id}")
	public void updateMenu(@PathVariable String id, @RequestParam("title") String title,
			@RequestParam("contents") String contents) {
		jwtMapper.updateMemo(id, title, contents);
	}

	@RequestMapping(method = RequestMethod.DELETE, path = "/menu/{id}")
	public void selectMenu(@PathVariable String id) {
		jwtMapper.deleteMemo(id);
	}

	@RequestMapping(method = RequestMethod.GET, path = "/use-type")
	public String selectUseType() {
		Gson gson = new Gson();
		String result = gson.toJson(jwtMapper.selectComcode(1), List.class);
		return result;
	}

	@RequestMapping(method = RequestMethod.GET, path = "/use-purs")
	public String selectUsePurs() {
		Gson gson = new Gson();
		String result = gson.toJson(jwtMapper.selectComcode(2), List.class);
		return result;
	}

	@RequestMapping(method = RequestMethod.GET, path = "/car-list")
	public String selectCarList() {
		Gson gson = new Gson();
		String result = gson.toJson(jwtMapper.selectComcode(3), List.class);
		return result;
	}

	@RequestMapping(method = RequestMethod.GET, path = "/car-use-hist")
	public String selectCarUseHistList(
			@RequestParam(required = false, defaultValue = "", name = "datefrom") String datefrom,
			@RequestParam(required = false, defaultValue = "", name = "dateto") String dateto,
			@RequestParam(required = false, defaultValue = "", name = "driverdept") String driverdept,
			@RequestParam(required = false, defaultValue = "", name = "drivernm") String drivernm,
			@RequestParam(required = false, name = "usetype") Integer usetype,
			@RequestParam(required = false, name = "usepurs") Integer usepurs,
			@RequestParam(required = false, defaultValue = "", name = "dest") String dest,
			@RequestParam(required = false, defaultValue = "", name = "dropby") String dropby,
			@RequestParam(required = false, name = "carid") Integer carid) {

		CarUseHistParam carUseHistParam = new CarUseHistParam();
		if(carid != null)
			carUseHistParam.setCarid(carid);
		carUseHistParam.setDatefrom(datefrom.trim());
		carUseHistParam.setDateto(dateto.trim());
		carUseHistParam.setDest(dest.trim());
		carUseHistParam.setDriverdept(driverdept.trim());
		carUseHistParam.setDrivernm(drivernm.trim());
		carUseHistParam.setDropby(dropby.trim());
		if(usepurs != null)
			carUseHistParam.setUsepurs(usepurs);
		if(usetype != null)
			carUseHistParam.setUsetype(usetype);

		Gson gson = new Gson();
		String result = gson.toJson(jwtMapper.selectCarUseHist(carUseHistParam), List.class);
		return result;
	}
	

	@RequestMapping(method = RequestMethod.POST, path = "/car-use-hist")
	public void insertCarUseHist(@RequestBody CarUseHistParam carUseHistParam, HttpServletRequest request) {
		String username = jwtProvider.getUsernameFromRequest(request);
		carUseHistParam.setUsrid(username);
		jwtMapper.insertCarUseHist(carUseHistParam);
	}

}
