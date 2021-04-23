package org.owasp.dependencycheck.data.nvd.json;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.function.Predicate;


/**
 * Filter that only accepts valid {@linkplain DefCpeMatch} objects.
 *
 * @author Stephan Fuhrmann
 */
public class CpeMatchValidityFilter implements Predicate<DefCpeMatch> {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(CpeMatchValidityFilter.class);

    /**
     * The singleton instance.
     */
    private static final CpeMatchValidityFilter INSTANCE;

    static {
        INSTANCE = new CpeMatchValidityFilter();
    }

    public static CpeMatchValidityFilter getInstance() {
        return INSTANCE;
    }

    @Override
    public boolean test(DefCpeMatch defCpeMatch) {
        boolean result = true;
        if (defCpeMatch != null) {
            if (defCpeMatch.getCpe23Uri() == null) {
                LOGGER.warn("cpe23uri is null: {}", defCpeMatch);
                result = false;
            }
        } else {
            LOGGER.warn("Reference is null");
            result = false;
        }
        return result;
    }
}
