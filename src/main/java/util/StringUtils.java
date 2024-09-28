package util;

import lombok.experimental.UtilityClass;

@UtilityClass
public class StringUtils {

    public boolean isEmpty(String s) {
        return s == null || s.isEmpty();
    }

    public boolean isNonEmpty(String s) {
        return !isEmpty(s);
    }
}
