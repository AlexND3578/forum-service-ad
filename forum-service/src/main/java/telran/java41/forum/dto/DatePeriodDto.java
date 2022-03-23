package telran.java41.forum.dto;

import java.time.LocalDate;

import com.fasterxml.jackson.annotation.JsonFormat;

import lombok.Getter;

@Getter
public class DatePeriodDto {

	@JsonFormat(pattern = "yyyy-MM-dd")
	LocalDate dateFrom;
	@JsonFormat(pattern = "yyyy-MM-dd")
	LocalDate dateTo;
}
